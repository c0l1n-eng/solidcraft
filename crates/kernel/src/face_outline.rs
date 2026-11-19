//! Faces as flat outlines, for cutting files (Export Face as DXF): the boundary of the picked
//! faces as closed 2D loops of lines and arcs.
//!
//! Faces that are all flat and on one plane keep their exact edges: a line is a line, a circle or
//! an arc of one is an arc, and any other edge is a chain of short lines within the tolerance.
//! Several such faces are joined into one outline where they meet. Faces that are curved, or flat
//! on different planes, are laid flat first ([`crate::flatten_surface`]), each connected patch a
//! piece of straight sides beside the last, with its stretch in [`FaceOutline::pieces`].

use solidcore_record::brep::{self as b, Curve};
use solidcore_record::{Loop2, Plane, Region2, Seg2, Vec2, Vec3};
use solidcraft_geom::brep::eval::CurveEval;
use solidcraft_geom::prelude::*;

use crate::body::Body;
use crate::{FlatInfo, KernelError, Result};

/// The picked faces as flat outlines.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FaceOutline {
    /// Each region: an outer loop and its holes (mm, in the outline's own plane).
    pub regions: Vec<Region2>,
    /// The faces' plane when they were all on one, the outline's coordinates being in it; `None`
    /// when they were laid flat.
    pub plane: Option<Plane>,
    /// The flattened pieces, when the faces were laid flat: what each is and how far it stretched.
    pub pieces: Vec<FlatInfo>,
}

/// The faces `faces` of `body` (indices in its face order) as flat outlines; `tolerance` (mm) is
/// how far a chain of lines may stand off a curved edge, and the flattening's tolerance (0 picks
/// one from the body's size).
pub fn face_outline(body: &Body, faces: &[usize], tolerance: f64) -> Result<FaceOutline> {
    body.require_brep("face outline")?;
    if !(tolerance.is_finite() && (0.0..=10.0).contains(&tolerance)) {
        return Err(KernelError::Invalid("the outline tolerance must be 0…10 mm".into()));
    }
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
    let Some(&first) = picked.first() else {
        return Err(KernelError::Invalid("pick the faces to outline".into()));
    };
    let chord = if tolerance > 0.0 { tolerance } else { (body.size() * 1e-5).max(1e-4) };
    if let Some(plane) = shared_plane(body, &picked, first) {
        let mut regions = Vec::new();
        for &f in &picked {
            regions.extend(planar_regions(body, f, &plane, chord)?);
        }
        if regions.len() > 1 {
            regions = crate::planar_regions_boolean(&regions, &[], crate::BoolOp::Union, chord.max(1e-6))?;
        }
        return Ok(FaceOutline { regions, plane: Some(plane), pieces: Vec::new() });
    }
    let flat = crate::flatten_surface(body, &picked, tolerance)?;
    let gap = (body.size() * 0.1).max(1.0);
    let mut x = 0.0;
    let mut regions = Vec::new();
    let mut pieces = Vec::new();
    for (_, info) in flat {
        let ring = |pts: &[[f64; 2]]| Loop2::polygon(&pts.iter().map(|&[u, v]| Vec2 { x: u + x, y: v }).collect::<Vec<_>>());
        regions.push(Region2 { outer: ring(&info.outer), holes: info.holes.iter().map(|h| ring(h)).collect() });
        x += info.extent[0] + gap;
        pieces.push(info);
    }
    Ok(FaceOutline { regions, plane: None, pieces })
}

/// The plane of face `first` when every picked face is flat on it.
fn shared_plane(body: &Body, picked: &[usize], first: usize) -> Option<Plane> {
    let plane = body.planar_face(first)?;
    let n = plane.x.cross(plane.y).normalized()?;
    let tol = (body.size() * 1e-7).max(1e-6);
    for &f in picked {
        let other = body.planar_face(f)?;
        let m = other.x.cross(other.y).normalized()?;
        if n.dot(m) < 1.0 - 1e-9 || (other.origin - plane.origin).dot(n).abs() > tol {
            return None;
        }
    }
    Some(plane)
}

/// Face `f`'s loops in `plane`'s coordinates, as regions: the loop of the largest area the outer
/// one, the others its holes.
fn planar_regions(body: &Body, f: usize, plane: &Plane, chord: f64) -> Result<Vec<Region2>> {
    let r = body.record();
    let face = r.faces.get(f).ok_or_else(|| KernelError::Invalid("no such face".into()))?;
    let mut loops: Vec<Loop2> = Vec::new();
    for lp in &face.loops {
        let b::Loop::Edges { edges } = lp else { continue };
        let mut segs = Vec::new();
        for oe in edges {
            let edge = r.edges.get(oe.edge as usize).ok_or_else(|| KernelError::Invalid("an edge out of range".into()))?;
            segs.extend(edge_segs(edge, oe.forward, plane, chord)?);
        }
        if !segs.is_empty() {
            loops.push(Loop2 { segs });
        }
    }
    loops.sort_by(|a, b| loop_area(b).abs().total_cmp(&loop_area(a).abs()));
    let mut it = loops.into_iter();
    let Some(outer) = it.next() else { return Ok(Vec::new()) };
    Ok(vec![Region2 { outer, holes: it.collect() }])
}

fn to_plane(plane: &Plane, p: Vec3) -> Vec2 {
    let d = p - plane.origin;
    Vec2 { x: d.dot(plane.x), y: d.dot(plane.y) }
}

/// An edge in the plane, in the direction it is used: a line, an arc, or a chain of lines.
fn edge_segs(edge: &b::Edge, forward: bool, plane: &Plane, chord: f64) -> Result<Vec<Seg2>> {
    // The interval is in the parameter of the edge's NURBS form when it has one.
    let eval = CurveEval::new(edge.nurbs.as_ref().unwrap_or(&edge.curve)).map_err(|e| KernelError::Invalid(format!("an edge: {e:?}")))?;
    let [t0, t1] = edge.interval;
    let (ts, te) = if forward { (t0, t1) } else { (t1, t0) };
    let at = |t: f64| eval.point(t).map(|p| to_plane(plane, p)).ok_or_else(|| KernelError::Invalid("an edge does not evaluate".into()));
    match &edge.curve {
        Curve::Line { .. } => Ok(vec![Seg2::Line { a: at(ts)?, b: at(te)? }]),
        Curve::Circle { frame, radius } => {
            let center = to_plane(plane, Vec3::new(frame.origin[0], frame.origin[1], frame.origin[2]));
            let (a, q, z) = (at(ts)?, at(ts + (te - ts) / 4.0)?, at(te)?);
            let angle = |p: Vec2| (p.y - center.y).atan2(p.x - center.x);
            let (aa, aq, az) = (angle(a), angle(q), angle(z));
            let turn = |x: f64| x.rem_euclid(std::f64::consts::TAU);
            // A quarter of the way along is less than half a turn on, the way the edge goes.
            let ccw = turn(aq - aa) < std::f64::consts::PI;
            // A closed edge (one vertex at both ends) is the whole circle.
            let whole = edge.vertices[0] == edge.vertices[1];
            let sweep = match (ccw, whole) {
                (true, true) => std::f64::consts::TAU,
                (false, true) => -std::f64::consts::TAU,
                (true, false) => turn(az - aa),
                (false, false) => -turn(aa - az),
            };
            Ok(vec![Seg2::Arc { center, radius: *radius, start: aa, sweep }])
        }
        _ => {
            // Sampled finely enough that no chord strays by more than `chord`: halving until the
            // middle of each piece is within it, at most 4096 pieces.
            let mut ts_list = vec![ts, te];
            for _ in 0..12 {
                let mut next = Vec::with_capacity(ts_list.len() * 2);
                let mut split = false;
                for (&p, &q) in ts_list.iter().zip(ts_list.iter().skip(1)) {
                    next.push(p);
                    let m = (p + q) / 2.0;
                    let (a, z, mid) = (at(p)?, at(q)?, at(m)?);
                    let off = off_line(mid, a, z);
                    if off > chord {
                        next.push(m);
                        split = true;
                    }
                }
                if let Some(last) = ts_list.last() {
                    next.push(*last);
                }
                ts_list = next;
                if !split {
                    break;
                }
            }
            let pts = ts_list.iter().map(|&t| at(t)).collect::<Result<Vec<_>>>()?;
            Ok(pts.iter().zip(pts.iter().skip(1)).map(|(&a, &b)| Seg2::Line { a, b }).collect())
        }
    }
}

fn off_line(p: Vec2, a: Vec2, b: Vec2) -> f64 {
    let (ab, ap) = (Vec2 { x: b.x - a.x, y: b.y - a.y }, Vec2 { x: p.x - a.x, y: p.y - a.y });
    let len2 = ab.x * ab.x + ab.y * ab.y;
    if len2 <= 0.0 {
        return (ap.x * ap.x + ap.y * ap.y).sqrt();
    }
    let t = ((ap.x * ab.x + ap.y * ab.y) / len2).clamp(0.0, 1.0);
    let (dx, dy) = (ap.x - t * ab.x, ap.y - t * ab.y);
    (dx * dx + dy * dy).sqrt()
}

/// Signed area of a loop, its arcs and curves by their ends (enough to tell outer from hole).
fn loop_area(lp: &Loop2) -> f64 {
    let mut pts: Vec<Vec2> = Vec::new();
    for s in &lp.segs {
        match *s {
            Seg2::Line { a, .. } => pts.push(a),
            Seg2::Arc { center, radius, start, sweep } => {
                for k in 0..8 {
                    let t = start + sweep * f64::from(k) / 8.0;
                    pts.push(Vec2 { x: center.x + radius * t.cos(), y: center.y + radius * t.sin() });
                }
            }
            _ => pts.push(s.start()),
        }
    }
    let next = pts.iter().cycle().skip(1);
    pts.iter().zip(next).map(|(a, b)| a.x * b.y - b.x * a.y).sum::<f64>() / 2.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{box_solid, cylinder};

    fn face_at(b: &Body, p: Vec3) -> usize {
        crate::surfaces::nearest_face(b, p).unwrap()
    }

    /// A box's top is one square of four lines in its own plane.
    #[test]
    fn a_box_top_is_its_square() {
        let b = box_solid(Vec3::ZERO, Vec3::new(30.0, 20.0, 10.0)).unwrap();
        let o = face_outline(&b, &[face_at(&b, Vec3::new(5.0, 5.0, 10.0))], 0.0).unwrap();
        assert!(o.plane.is_some() && o.pieces.is_empty());
        assert_eq!(o.regions.len(), 1);
        let r = &o.regions[0];
        assert_eq!(r.outer.segs.len(), 4);
        assert!(r.holes.is_empty());
        assert!((loop_area(&r.outer).abs() - 600.0).abs() < 1e-9);
    }

    /// A plate with a round hole through it: its top is a rectangle with a circle for a hole, the
    /// circle one exact arc.
    #[test]
    fn a_hole_in_a_plate_is_an_exact_circle() {
        let plate = box_solid(Vec3::ZERO, Vec3::new(40.0, 30.0, 5.0)).unwrap();
        let pin = cylinder(Vec3::new(20.0, 15.0, -1.0), Vec3::new(0.0, 0.0, 1.0), 4.0, 7.0).unwrap();
        let holed = crate::boolean(&plate, &pin, crate::BoolOp::Cut).unwrap().unwrap();
        let top = face_at(&holed, Vec3::new(2.0, 2.0, 5.0));
        let o = face_outline(&holed, &[top], 0.0).unwrap();
        assert_eq!(o.regions.len(), 1);
        let r = &o.regions[0];
        assert_eq!(r.holes.len(), 1, "{r:?}");
        let arcs: f64 = r.holes[0]
            .segs
            .iter()
            .map(|s| match s {
                Seg2::Arc { radius, sweep, .. } => {
                    assert!((radius - 4.0).abs() < 1e-9);
                    sweep.abs()
                }
                other => panic!("not an arc: {other:?}"),
            })
            .sum();
        assert!((arcs - std::f64::consts::TAU).abs() < 1e-9, "{arcs}");
    }

    /// A cylinder's side is laid flat first: one piece, its stretch reported.
    #[test]
    fn a_curved_face_is_laid_flat() {
        let c = cylinder(Vec3::ZERO, Vec3::new(0.0, 0.0, 1.0), 10.0, 20.0).unwrap();
        let o = face_outline(&c, &[face_at(&c, Vec3::new(10.0, 0.0, 10.0))], 0.0).unwrap();
        assert!(o.plane.is_none());
        assert_eq!((o.regions.len(), o.pieces.len()), (1, 1));
        assert!(o.pieces[0].max_stretch < 1e-3);
    }

    #[test]
    fn hostile_picks_are_refused() {
        let b = box_solid(Vec3::ZERO, Vec3::new(10.0, 10.0, 10.0)).unwrap();
        assert!(face_outline(&b, &[], 0.0).is_err());
        assert!(face_outline(&b, &[99], 0.0).is_err());
        assert!(face_outline(&b, &[0], f64::NAN).is_err());
    }
}
