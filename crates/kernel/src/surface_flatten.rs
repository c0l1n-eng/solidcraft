//! Flattened surfaces (Surface › Flatten): faces of a body laid flat in the plane as new flat
//! surface bodies, for labels, decals and wraps. Faces that share an edge stay joined, one flat
//! piece per connected patch. The pieces lie on the plane through the bottom of the body's box,
//! side by side beyond its +X side.
//!
//! The flattening is solidcore-tess's ([`solidcore_tess::flatten_faces`]): a plane, cylinder or
//! cone comes out at its true size to within the mesh tolerance; a dome or a saddle with the
//! least stretch it finds, which [`FlatInfo`] reports. Each piece is an exact planar face
//! bounded by straight sides.

use solidcore_record::{Loop2, Plane, Region2, Vec2, Vec3};

use crate::body::Body;
use crate::{KernelError, Result};

/// The triangles a flattening aims for over the picked faces.
const TRIANGLES: f64 = 6000.0;

/// What one flat piece is, beside its body.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlatInfo {
    /// The source faces in the piece (indices in the body's face order of the copy, ascending).
    pub faces: Vec<u32>,
    /// Width and height of the piece (mm).
    pub extent: [f64; 2],
    /// Area of the faces in space (mm²), as meshed.
    pub area_3d: f64,
    /// Area of the flat piece (mm²), as meshed.
    pub area_flat: f64,
    /// Area-weighted mean stretch, as a fraction (0.01 is 1 %).
    pub mean_stretch: f64,
    /// The largest stretch at any point, as a fraction.
    pub max_stretch: f64,
    /// Triangles that came out turned over: the piece overlaps itself.
    pub folded: usize,
    /// The piece's outer boundary, counter-clockwise, its smallest corner at (0, 0) (mm).
    pub outer: Vec<[f64; 2]>,
    /// Its holes, clockwise, in the same coordinates.
    pub holes: Vec<Vec<[f64; 2]>>,
}

/// The picked faces of `body` (indices in its face order) laid flat: one planar surface body per
/// connected patch, with what each is. `tolerance` (mm): the mesh's chord, and the most a flat
/// outline may stand off the flattened mesh's; 0 picks one from the body's size.
pub fn flatten_surface(body: &Body, faces: &[usize], tolerance: f64) -> Result<Vec<(Body, FlatInfo)>> {
    body.require_brep("flatten")?;
    let count = body.face_count();
    let mut picked: Vec<usize> = Vec::new();
    for &i in faces {
        if i >= count {
            return Err(KernelError::Invalid("no such face".into()));
        }
        if !picked.contains(&i) {
            picked.push(i);
        }
    }
    if picked.is_empty() {
        return Err(KernelError::Invalid("pick the faces to flatten".into()));
    }
    if !(tolerance.is_finite() && (0.0..=10.0).contains(&tolerance)) {
        return Err(KernelError::Invalid("the flatten tolerance must be 0…10 mm".into()));
    }
    let size = body.size();
    if !(size.is_finite() && size > 0.0) {
        return Err(KernelError::Invalid("the body has no size".into()));
    }
    // The picked faces on their own: a copy of them, so only they are meshed.
    let copy = crate::offset_surface(body, &picked, 0.0, (size * 1e-6).clamp(1e-6, 0.01))?;
    let all: Vec<u32> = (0..copy.face_count()).filter_map(|f| u32::try_from(f).ok()).collect();
    // About TRIANGLES triangles over the faces: enough for a label's outline, few enough to solve
    // at once. The chord follows the side, unless a tolerance is asked.
    let area = crate::measure(&copy)?.area;
    let side = (area / (TRIANGLES * 0.433)).sqrt().max(size * 1e-4);
    let chord = if tolerance > 0.0 { tolerance.max(size * 1e-7) } else { (side * 0.02).max(size * 1e-5) };
    let spec = solidcore_tess::MeshSpec { chord, size: Some(side), min_angle: solidcore_tess::MESH_MIN_ANGLE };
    let pieces = crate::guard("flatten", || solidcore_tess::flatten_faces(copy.record(), &all, &spec, copy.size()).map_err(KernelError::from))?;
    // Side by side beyond the body's +X side, a tenth of its size apart.
    let bounds = body.exact_bounds()?;
    let gap = (size * 0.1).max(1.0);
    let mut x = bounds.max.x + gap;
    let mut out = Vec::with_capacity(pieces.len());
    for p in pieces {
        let plane = Plane { origin: Vec3::new(x, bounds.min.y, bounds.min.z), x: Vec3::new(1.0, 0.0, 0.0), y: Vec3::new(0.0, 1.0, 0.0) };
        let ring = |pts: &[[f64; 2]]| Loop2::polygon(&pts.iter().map(|&[u, v]| Vec2 { x: u, y: v }).collect::<Vec<_>>());
        let region = Region2 { outer: ring(&p.outer), holes: p.holes.iter().map(|h| ring(h)).collect() };
        let flat = crate::patch_region(&plane, &region)?;
        x += p.extent[0] + gap;
        let info = FlatInfo {
            faces: p.faces,
            extent: p.extent,
            area_3d: p.area_3d,
            area_flat: p.area_flat,
            mean_stretch: p.mean_stretch,
            max_stretch: p.max_stretch,
            folded: p.folded,
            outer: p.outer,
            holes: p.holes,
        };
        out.push((flat, info));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{box_solid, cylinder, measure, sphere};

    fn face_at(b: &Body, p: Vec3) -> usize {
        crate::surfaces::nearest_face(b, p).unwrap()
    }

    /// A box's top is its own size, flat and beside the box; top and a side, joined across their
    /// edge, are one 10 × 20 piece.
    #[test]
    fn a_box_top_and_side_lay_flat_at_their_size() {
        let b = box_solid(Vec3::ZERO, Vec3::new(10.0, 10.0, 10.0)).unwrap();
        let top = face_at(&b, Vec3::new(5.0, 5.0, 10.0));
        let side = face_at(&b, Vec3::new(5.0, 0.0, 5.0));
        let one = flatten_surface(&b, &[top], 0.0).unwrap();
        assert_eq!(one.len(), 1);
        let (flat, info) = &one[0];
        let m = measure(flat).unwrap();
        assert!(flat.is_surface() && (m.area - 100.0).abs() < 1e-6, "{m:?}");
        assert!(m.bbox.min.x > 10.0 && (m.bbox.max.z - m.bbox.min.z).abs() < 1e-9 && m.bbox.min.z.abs() < 1e-9, "{m:?}");
        assert!(info.max_stretch < 1e-6 && info.folded == 0, "{info:?}");
        let two = flatten_surface(&b, &[top, side], 0.0).unwrap();
        assert_eq!(two.len(), 1, "joined across the shared edge");
        let mut e = two[0].1.extent;
        e.sort_by(f64::total_cmp);
        assert!((e[0] - 10.0).abs() < 1e-6 && (e[1] - 20.0).abs() < 1e-6, "{e:?}");
        assert!((measure(&two[0].0).unwrap().area - 200.0).abs() < 1e-6);
    }

    /// A cylinder's side (one face round its seam) unrolls to its height by its circumference.
    #[test]
    fn a_cylinder_side_unrolls_to_its_circumference() {
        let c = cylinder(Vec3::ZERO, Vec3::new(0.0, 0.0, 1.0), 10.0, 20.0).unwrap();
        let wall = face_at(&c, Vec3::new(10.0, 0.0, 10.0));
        let out = flatten_surface(&c, &[wall], 0.0).unwrap();
        assert_eq!(out.len(), 1);
        let (flat, info) = &out[0];
        let mut e = info.extent;
        e.sort_by(f64::total_cmp);
        let round = 2.0 * std::f64::consts::PI * 10.0;
        assert!((e[0] - 20.0).abs() < 1e-3, "{e:?}");
        assert!((e[1] - round).abs() < 0.03, "{e:?} vs {round}");
        assert!(info.max_stretch < 1e-3, "{info:?}");
        assert!((measure(flat).unwrap().area - 20.0 * round).abs() < 0.2);
    }

    /// A sphere (one face, cut open along its seam) cannot unroll: it lies flat with its stretch
    /// reported.
    #[test]
    fn a_sphere_reports_its_stretch() {
        let s = sphere(Vec3::ZERO, 20.0).unwrap();
        let faces: Vec<usize> = (0..s.face_count()).collect();
        let out = flatten_surface(&s, &faces, 0.0).unwrap();
        let info = &out[0].1;
        assert_eq!(out.len(), 1);
        assert!(info.mean_stretch > 0.05 && info.folded == 0, "{info:?}");
    }

    #[test]
    fn hostile_picks_are_refused() {
        let b = box_solid(Vec3::ZERO, Vec3::new(10.0, 10.0, 10.0)).unwrap();
        assert!(flatten_surface(&b, &[], 0.0).is_err());
        assert!(flatten_surface(&b, &[99], 0.0).is_err());
        assert!(flatten_surface(&b, &[0], f64::NAN).is_err());
        assert!(flatten_surface(&b, &[0], -1.0).is_err());
        let all: Vec<usize> = (0..b.face_count()).collect();
        assert!(flatten_surface(&b, &all, 0.0).is_err(), "a closed box has no edge to open");
    }
}
