//! Flattening faces into the plane (Surface › Flatten): a body's faces, joined where they share
//! an edge, laid flat as one piece per connected patch, for labels, decals and wraps.
//!
//! The faces are meshed on the mesh path ([`crate::mesh()`]) and joined at their shared edge
//! nodes ([`crate::TessPlan::welded`]); a seam (an edge a face runs on both sides, as on a
//! cylinder) is cut open. Each patch is then laid flat in two steps:
//!
//! 1. least-squares conformal maps (angles kept as well as they can be, two boundary points held
//!    apart by their distance in space) for a start that never folds;
//! 2. as-rigid-as-possible relaxation (each triangle as close to a rotated copy of itself as the
//!    others allow, solved by alternating its best rotation with one linear solve).
//!
//! A surface that unrolls without stretching (a plane, cylinder or cone) comes out at its true
//! size, to within the mesh's chord tolerance; one that cannot (a dome, a saddle) comes out with
//! the least stretch the relaxation finds, and the stretch is reported ([`FlatPiece`]).
//!
//! Library code never panics, unwraps or indexes on input-derived data.

use std::collections::{BTreeMap, HashMap};

use solidcore_record::Vec3;
use solidcore_record::brep;

use crate::{MeshSpec, Result, TessError};

/// The most triangles a flattening takes: beyond it the solve is too slow to wait for.
pub const MAX_FLATTEN_TRIANGLES: usize = 400_000;

/// Rounds of rigid relaxation at most.
const ROUNDS: usize = 60;

/// One flat piece: a connected patch of the picked faces laid in the plane.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlatPiece {
    /// The outer boundary, counter-clockwise, with its smallest corner at (0, 0) (mm).
    pub outer: Vec<[f64; 2]>,
    /// Holes, clockwise, in the same coordinates.
    pub holes: Vec<Vec<[f64; 2]>>,
    /// Width and height of the piece's box (mm).
    pub extent: [f64; 2],
    /// The B-rep faces in the piece (indices in the body's face order), ascending.
    pub faces: Vec<u32>,
    /// Area of the patch in space (mm²), as meshed.
    pub area_3d: f64,
    /// Area of the flat piece (mm²).
    pub area_flat: f64,
    /// Area-weighted mean stretch: how much a short length changes in the worst direction at
    /// each point, as a fraction (0.01 is 1 %).
    pub mean_stretch: f64,
    /// The largest stretch at any point, as a fraction.
    pub max_stretch: f64,
    /// Triangles that came out turned over (the piece overlaps itself there).
    pub folded: usize,
}

/// The faces `faces` of `b` (indices in its face order), a body of size `size` (its box
/// diagonal), meshed to `spec` and laid flat: one [`FlatPiece`] per connected patch, in the
/// order of each patch's smallest face index.
///
/// # Errors
/// [`TessError::Invalid`] for no faces or a face index out of range; [`TessError::Failed`] when
/// a picked face cannot be meshed, a patch is closed (it has no boundary to open it along: pick
/// fewer faces), or the mesh is larger than [`MAX_FLATTEN_TRIANGLES`].
pub fn flatten_faces(
    b: &brep::Brep,
    faces: &[u32],
    spec: &MeshSpec,
    size: f64,
) -> Result<Vec<FlatPiece>> {
    if faces.is_empty() {
        return Err(TessError::Invalid("flatten: no faces".into()));
    }
    if let Some(f) = faces.iter().find(|&&f| f as usize >= b.faces.len()) {
        return Err(TessError::Invalid(format!("flatten: no face {f}")));
    }
    let (plan, _) = crate::mesh(b, spec, size, None)?;
    let (welded, refused) = plan.welded()?;
    if let Some(r) = refused.iter().find(|r| faces.contains(&(r.face as u32))) {
        return Err(TessError::Failed(format!(
            "flatten: face {}: {}",
            r.face, r.reason
        )));
    }
    // Seams: an edge only one face runs (on both of its sides) is cut open.
    let mut cuts = Vec::new();
    for (e, line) in welded.edges.iter().enumerate() {
        let Some(on) = plan.edge_faces.get(e) else {
            continue;
        };
        let first = on.first().copied();
        if first.is_some_and(|f| faces.contains(&f) && on.iter().all(|&g| g == f)) {
            cuts.push(line.clone());
        }
    }
    let mut triangles = Vec::new();
    let mut tri_face = Vec::new();
    for (t, f) in welded.triangles.iter().zip(&welded.tri_face) {
        if faces.contains(f) {
            triangles.push(*t);
            tri_face.push(*f);
        }
    }
    flatten_mesh(&welded.positions, &triangles, &tri_face, &cuts, spec.chord)
}

/// A triangle mesh laid flat: `triangles` (counter-clockwise seen from the side that is to face
/// up) over `positions`, each tagged with its B-rep face in `tri_face`, cut open along the
/// vertex chains `cuts`, one [`FlatPiece`] per connected patch. Boundaries are simplified to
/// `tolerance` (mm): points that stand off the straight line between their neighbours by less
/// are dropped.
///
/// # Errors
/// [`TessError::Invalid`] for an index out of range or a tag list of the wrong length;
/// [`TessError::Failed`] for no triangles with area, a closed patch, or more than
/// [`MAX_FLATTEN_TRIANGLES`] triangles.
pub fn flatten_mesh(
    positions: &[Vec3],
    triangles: &[[u32; 3]],
    tri_face: &[u32],
    cuts: &[Vec<u32>],
    tolerance: f64,
) -> Result<Vec<FlatPiece>> {
    if triangles.len() != tri_face.len() {
        return Err(TessError::Invalid(
            "flatten: one face tag per triangle".into(),
        ));
    }
    if triangles.len() > MAX_FLATTEN_TRIANGLES {
        return Err(TessError::Failed(format!(
            "flatten: {} triangles, more than {MAX_FLATTEN_TRIANGLES}",
            triangles.len()
        )));
    }
    if !(tolerance.is_finite() && tolerance > 0.0) {
        return Err(TessError::Invalid(format!(
            "flatten: a tolerance of {tolerance} mm"
        )));
    }
    let pts: Vec<[f64; 3]> = positions.iter().map(|p| [p.x, p.y, p.z]).collect();
    if pts.iter().flatten().any(|x| !x.is_finite()) {
        return Err(TessError::Invalid(
            "flatten: a position is not finite".into(),
        ));
    }
    // Triangles with area, by their corners' positions.
    let mut tris: Vec<[usize; 3]> = Vec::with_capacity(triangles.len());
    let mut tags: Vec<u32> = Vec::with_capacity(triangles.len());
    for (t, &f) in triangles.iter().zip(tri_face) {
        let c = t.map(|i| i as usize);
        let (Some(a), Some(b), Some(d)) = (pts.get(c[0]), pts.get(c[1]), pts.get(c[2])) else {
            return Err(TessError::Invalid("flatten: a corner out of range".into()));
        };
        let area2 = norm3(cross3(sub3(*b, *a), sub3(*d, *a)));
        let scale = norm3(sub3(*b, *a)).max(norm3(sub3(*d, *a)));
        if area2 > 1e-12 * scale * scale && c[0] != c[1] && c[1] != c[2] && c[0] != c[2] {
            tris.push(c);
            tags.push(f);
        }
    }
    if tris.is_empty() {
        return Err(TessError::Failed(
            "flatten: nothing with area to flatten".into(),
        ));
    }
    let (verts, tris) = cut_open(&pts, &tris, cuts)?;
    let mut pieces = Vec::new();
    for group in components(&tris) {
        let piece = flatten_patch(&verts, &tris, &tags, &group, tolerance)?;
        pieces.push(piece);
    }
    pieces.sort_by_key(|p| p.faces.first().copied());
    Ok(pieces)
}

// ---- Topology ---------------------------------------------------------------------------

/// Disjoint sets over `0..n`.
struct Sets(Vec<usize>);

impl Sets {
    fn new(n: usize) -> Self {
        Sets((0..n).collect())
    }
    fn find(&mut self, mut i: usize) -> usize {
        while let Some(&p) = self.0.get(i) {
            if p == i {
                break;
            }
            let up = self.0.get(p).copied().unwrap_or(p);
            if let Some(slot) = self.0.get_mut(i) {
                *slot = up;
            }
            i = p;
        }
        i
    }
    fn join(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb
            && let Some(slot) = self.0.get_mut(ra.max(rb))
        {
            *slot = ra.min(rb);
        }
    }
}

fn key(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

/// The mesh with its vertices split wherever the triangles around them do not meet across an
/// edge that stays joined: along `cuts`, along edges more than two triangles share or two
/// triangles run the same way, and at vertices where two fans touch. Returns the new positions
/// and triangles (the same triangles in the same order).
fn cut_open(pts: &[[f64; 3]], tris: &[[usize; 3]], cuts: &[Vec<u32>]) -> Result<Opened> {
    let mut cut: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for line in cuts {
        for w in line.windows(2) {
            if let [a, b] = w {
                cut.insert(key(*a as usize, *b as usize));
            }
        }
    }
    // Each edge's uses: (triangle, slot of its first corner going round the triangle).
    let mut uses: BTreeMap<(usize, usize), Vec<(usize, usize)>> = BTreeMap::new();
    for (t, c) in tris.iter().enumerate() {
        for k in 0..3 {
            let (a, b) = (corner(c, k), corner(c, k + 1));
            uses.entry(key(a, b)).or_default().push((t, k));
        }
    }
    // Corners 3t + k; corners that are one vertex across a joined edge are one set.
    let mut sets = Sets::new(tris.len() * 3);
    for (edge, on) in &uses {
        let [(t1, k1), (t2, k2)] = on.as_slice() else {
            continue;
        };
        if cut.contains(edge) {
            continue;
        }
        let (Some(c1), Some(c2)) = (tris.get(*t1), tris.get(*t2)) else {
            continue;
        };
        // Joined only where the two run the edge opposite ways (a consistent orientation).
        let (a1, b1) = (corner(c1, *k1), corner(c1, k1 + 1));
        let (a2, b2) = (corner(c2, *k2), corner(c2, k2 + 1));
        if a1 == b2 && b1 == a2 {
            sets.join(3 * t1 + k1, 3 * t2 + (k2 + 1) % 3);
            sets.join(3 * t1 + (k1 + 1) % 3, 3 * t2 + k2);
        }
    }
    let mut number: HashMap<usize, usize> = HashMap::new();
    let mut verts: Vec<[f64; 3]> = Vec::new();
    let mut out = Vec::with_capacity(tris.len());
    for (t, c) in tris.iter().enumerate() {
        let mut nt = [0usize; 3];
        for (k, slot) in nt.iter_mut().enumerate() {
            let root = sets.find(3 * t + k);
            let id = if let Some(&id) = number.get(&root) {
                id
            } else {
                let p = pts
                    .get(corner(c, k))
                    .copied()
                    .ok_or_else(|| TessError::Invalid("flatten: a corner out of range".into()))?;
                verts.push(p);
                number.insert(root, verts.len() - 1);
                verts.len() - 1
            };
            *slot = id;
        }
        out.push(nt);
    }
    Ok((verts, out))
}

/// A mesh cut open: its positions and its triangles.
type Opened = (Vec<[f64; 3]>, Vec<[usize; 3]>);

/// Corner `k` (mod 3) of a triangle.
fn corner(c: &[usize; 3], k: usize) -> usize {
    c.get(k % 3).copied().unwrap_or_default()
}

/// The triangles in connected patches (sharing an edge), each list ascending, in the order of
/// their first triangle.
fn components(tris: &[[usize; 3]]) -> Vec<Vec<usize>> {
    let mut sets = Sets::new(tris.len());
    let mut by_edge: HashMap<(usize, usize), usize> = HashMap::new();
    for (t, c) in tris.iter().enumerate() {
        for k in 0..3 {
            let e = key(corner(c, k), corner(c, k + 1));
            match by_edge.get(&e) {
                Some(&o) => sets.join(o, t),
                None => {
                    by_edge.insert(e, t);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for t in 0..tris.len() {
        let r = sets.find(t);
        groups.entry(r).or_default().push(t);
    }
    groups.into_values().collect()
}

/// The boundary loops of triangles `tris` over local vertices, each in the triangles' own
/// direction.
fn boundary_loops(tris: &[[usize; 3]]) -> Vec<Vec<usize>> {
    let mut half: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for c in tris {
        for k in 0..3 {
            half.insert((corner(c, k), corner(c, k + 1)));
        }
    }
    let mut next: BTreeMap<usize, usize> = BTreeMap::new();
    for &(a, b) in &half {
        if !half.contains(&(b, a)) {
            next.insert(a, b);
        }
    }
    let mut loops = Vec::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for &start in next.keys() {
        if seen.contains(&start) {
            continue;
        }
        let mut lp = Vec::new();
        let mut at = start;
        while seen.insert(at) {
            lp.push(at);
            match next.get(&at) {
                Some(&n) => at = n,
                None => break,
            }
        }
        if lp.len() >= 3 {
            loops.push(lp);
        }
    }
    loops
}

// ---- One patch --------------------------------------------------------------------------

/// A triangle in its own plane: its corners' coordinates in an orthonormal frame of it, and
/// its area.
#[derive(Clone, Copy)]
struct Local {
    q: [[f64; 2]; 3],
    area: f64,
}

fn local(p: [[f64; 3]; 3]) -> Local {
    let [p0, p1, p2] = p;
    let e1 = sub3(p1, p0);
    let e2 = sub3(p2, p0);
    let l1 = norm3(e1);
    let n = cross3(e1, e2);
    let area = 0.5 * norm3(n);
    let x = scale3(e1, 1.0 / l1);
    let y = cross3(n, x);
    let y = scale3(y, 1.0 / norm3(y));
    Local {
        q: [[0.0, 0.0], [l1, 0.0], [dot3(e2, x), dot3(e2, y)]],
        area,
    }
}

fn flatten_patch(
    verts: &[[f64; 3]],
    tris: &[[usize; 3]],
    tags: &[u32],
    group: &[usize],
    tolerance: f64,
) -> Result<FlatPiece> {
    // Local numbering of the patch's vertices.
    let mut index: BTreeMap<usize, usize> = BTreeMap::new();
    let mut tri: Vec<[usize; 3]> = Vec::with_capacity(group.len());
    let mut faces: Vec<u32> = Vec::new();
    for &t in group {
        let Some(c) = tris.get(t) else { continue };
        let mut lt = [0usize; 3];
        for (slot, &v) in lt.iter_mut().zip(c) {
            let n = index.len();
            *slot = *index.entry(v).or_insert(n);
        }
        tri.push(lt);
        if let Some(&f) = tags.get(t)
            && !faces.contains(&f)
        {
            faces.push(f);
        }
    }
    faces.sort_unstable();
    let mut p3 = vec![[0.0; 3]; index.len()];
    for (&global, &l) in &index {
        if let (Some(slot), Some(p)) = (p3.get_mut(l), verts.get(global)) {
            *slot = *p;
        }
    }
    let n = p3.len();
    let loops = boundary_loops(&tri);
    if loops.is_empty() {
        return Err(TessError::Failed(format!(
            "flatten: the faces {faces:?} close up, with no edge to open them along; pick fewer faces"
        )));
    }
    let locals: Vec<Local> = tri
        .iter()
        .map(|c| local([at3(&p3, c[0]), at3(&p3, c[1]), at3(&p3, c[2])]))
        .collect();
    // Hold the two boundary points farthest apart (roughly: from the first, the farthest; from
    // it, the farthest), at their distance in space.
    let boundary: Vec<usize> = loops.iter().flatten().copied().collect();
    let far = |from: usize| {
        boundary
            .iter()
            .copied()
            .max_by(|&a, &b| {
                let da = norm3(sub3(at3(&p3, a), at3(&p3, from)));
                let db = norm3(sub3(at3(&p3, b), at3(&p3, from)));
                da.total_cmp(&db)
            })
            .unwrap_or(from)
    };
    let first = boundary.first().copied().unwrap_or_default();
    let a = far(first);
    let b = far(a);
    let span = norm3(sub3(at3(&p3, a), at3(&p3, b)));
    if span.is_nan() || span <= 0.0 {
        return Err(TessError::Failed("flatten: the patch has no extent".into()));
    }
    let mut uv = lscm(n, &tri, &locals, (a, [0.0, 0.0]), (b, [span, 0.0]))?;
    arap(&mut uv, &tri, &locals, tolerance);
    // Face up: the triangles counter-clockwise in the plane, as they were seen from outside.
    let signed: f64 = tri
        .iter()
        .map(|c| signed_area(at2(&uv, c[0]), at2(&uv, c[1]), at2(&uv, c[2])))
        .sum();
    if signed < 0.0 {
        for p in &mut uv {
            p[0] = -p[0];
        }
    }
    // Stretch from each triangle's map.
    let mut area_3d = 0.0;
    let mut area_flat = 0.0;
    let mut weighted = 0.0;
    let mut max_stretch: f64 = 0.0;
    let mut folded = 0;
    for (c, l) in tri.iter().zip(&locals) {
        let (u0, u1, u2) = (at2(&uv, c[0]), at2(&uv, c[1]), at2(&uv, c[2]));
        let s_area = signed_area(u0, u1, u2);
        area_3d += l.area;
        area_flat += s_area.abs();
        if s_area <= 0.0 {
            folded += 1;
        }
        let (s1, s2) = singular_values(l, u0, u1, u2);
        let stretch = (s1 - 1.0).abs().max((s2 - 1.0).abs());
        weighted += stretch * l.area;
        max_stretch = max_stretch.max(stretch);
    }
    let mean_stretch = if area_3d > 0.0 {
        weighted / area_3d
    } else {
        0.0
    };
    // The loops in the plane, simplified; the outer one the largest.
    let mut flat: Vec<Vec<[f64; 2]>> = loops
        .iter()
        .map(|lp| {
            simplify(
                &lp.iter().map(|&v| at2(&uv, v)).collect::<Vec<_>>(),
                tolerance,
            )
        })
        .filter(|lp| lp.len() >= 3)
        .collect();
    flat.sort_by(|x, y| loop_area(y).abs().total_cmp(&loop_area(x).abs()));
    let mut it = flat.into_iter();
    let mut outer = it.next().unwrap_or_default();
    let mut holes: Vec<Vec<[f64; 2]>> = it.collect();
    if loop_area(&outer) < 0.0 {
        outer.reverse();
    }
    for h in &mut holes {
        if loop_area(h) > 0.0 {
            h.reverse();
        }
    }
    // Square to the axes: turned so its box is the smallest, an edge of the outline along x.
    let turn = squared(&outer);
    let rotate = |p: &mut [f64; 2]| {
        let ([c, s], [x, y]) = (turn, *p);
        *p = [c * x - s * y, s * x + c * y];
    };
    outer.iter_mut().for_each(rotate);
    holes.iter_mut().flatten().for_each(rotate);
    // Smallest corner at the origin.
    let (mut lo, mut hi) = ([f64::INFINITY; 2], [f64::NEG_INFINITY; 2]);
    for &[x, y] in &outer {
        lo = [lo[0].min(x), lo[1].min(y)];
        hi = [hi[0].max(x), hi[1].max(y)];
    }
    let shift = |p: &mut [f64; 2]| {
        let [x, y] = *p;
        *p = [x - lo[0], y - lo[1]];
    };
    outer.iter_mut().for_each(shift);
    holes.iter_mut().flatten().for_each(shift);
    Ok(FlatPiece {
        outer,
        holes,
        extent: [hi[0] - lo[0], hi[1] - lo[1]],
        faces,
        area_3d,
        area_flat,
        mean_stretch,
        max_stretch,
        folded,
    })
}

/// The rotation (cos, sin) that turns `outline` so its box is the smallest among the turns that
/// lay one of its sides along x (its widest side when two tie); the identity for no sides.
fn squared(outline: &[[f64; 2]]) -> [f64; 2] {
    // A long outline is sampled for candidate sides: its box is checked whole.
    let n = outline.len();
    let step = n.div_ceil(512).max(1);
    let mut best = ([1.0, 0.0], f64::INFINITY, 0.0);
    for i in (0..n).step_by(step) {
        let a = at2(outline, i);
        let b = at2(outline, (i + 1) % n);
        let d = sub2(b, a);
        let len = norm2(d);
        if len.is_nan() || len <= 0.0 {
            continue;
        }
        // Turn the side onto +x: by (cos, −sin) of its angle.
        let (c, s) = (d[0] / len, -d[1] / len);
        let (mut lo, mut hi) = ([f64::INFINITY; 2], [f64::NEG_INFINITY; 2]);
        for p in outline {
            let q = [c * p[0] - s * p[1], s * p[0] + c * p[1]];
            lo = [lo[0].min(q[0]), lo[1].min(q[1])];
            hi = [hi[0].max(q[0]), hi[1].max(q[1])];
        }
        let area = (hi[0] - lo[0]) * (hi[1] - lo[1]);
        let tie = (area - best.1).abs() <= 1e-9 * best.1.abs().max(1.0);
        if area < best.1 && !tie || tie && len > best.2 {
            best = ([c, s], area.min(best.1), len);
        }
    }
    best.0
}

/// Least-squares conformal map of the patch, `pin_a` and `pin_b` held where given.
fn lscm(
    n: usize,
    tri: &[[usize; 3]],
    locals: &[Local],
    pin_a: (usize, [f64; 2]),
    pin_b: (usize, [f64; 2]),
) -> Result<Vec<[f64; 2]>> {
    // Two rows per triangle over the unknowns 2v (u) and 2v + 1 (v).
    let mut rows: Vec<Vec<(usize, f64)>> = Vec::with_capacity(2 * tri.len());
    for (c, l) in tri.iter().zip(locals) {
        let s = 1.0 / (2.0 * l.area).sqrt();
        let mut re = Vec::with_capacity(6);
        let mut im = Vec::with_capacity(6);
        for k in 0..3 {
            let qa = l.q.get((k + 1) % 3).copied().unwrap_or_default();
            let qb = l.q.get((k + 2) % 3).copied().unwrap_or_default();
            // W = q(k+2) − q(k+1), as a complex number a + ib.
            let (wa, wb) = (qb[0] - qa[0], qb[1] - qa[1]);
            let v = corner(c, k);
            re.push((2 * v, s * wa));
            re.push((2 * v + 1, -s * wb));
            im.push((2 * v, s * wb));
            im.push((2 * v + 1, s * wa));
        }
        rows.push(re);
        rows.push(im);
    }
    let mut fixed: Vec<Option<f64>> = vec![None; 2 * n];
    for (v, p) in [pin_a, pin_b] {
        for (k, value) in p.into_iter().enumerate() {
            if let Some(slot) = fixed.get_mut(2 * v + k) {
                *slot = Some(value);
            }
        }
    }
    // Normal equations over the free unknowns: (AᵀA) x = −Aᵀ(A x_fixed).
    let free = |x: &[f64]| -> Vec<f64> {
        x.iter()
            .zip(&fixed)
            .map(|(v, f)| if f.is_some() { 0.0 } else { *v })
            .collect()
    };
    let apply = |x: &[f64]| -> Vec<f64> {
        let mut out = vec![0.0; x.len()];
        for row in &rows {
            let r: f64 = row
                .iter()
                .map(|&(j, c)| c * x.get(j).copied().unwrap_or(0.0))
                .sum();
            for &(j, c) in row {
                if let Some(o) = out.get_mut(j) {
                    *o += c * r;
                }
            }
        }
        out
    };
    let x_fixed: Vec<f64> = fixed.iter().map(|f| f.unwrap_or(0.0)).collect();
    let rhs: Vec<f64> = free(&apply(&x_fixed)).into_iter().map(|v| -v).collect();
    let mut diag = vec![0.0; 2 * n];
    for row in &rows {
        for &(j, c) in row {
            if let Some(d) = diag.get_mut(j) {
                *d += c * c;
            }
        }
    }
    let op = |x: &[f64]| free(&apply(&free(x)));
    let x = cg(&op, &rhs, &diag, vec![0.0; 2 * n], 1e-12, 20 * n + 200);
    let x: Vec<f64> = x.iter().zip(&fixed).map(|(v, f)| f.unwrap_or(*v)).collect();
    if x.iter().any(|v| !v.is_finite()) {
        return Err(TessError::Failed(
            "flatten: the conformal solve diverged".into(),
        ));
    }
    Ok(x.chunks(2)
        .map(|p| {
            [
                p.first().copied().unwrap_or(0.0),
                p.get(1).copied().unwrap_or(0.0),
            ]
        })
        .collect())
}

/// As-rigid-as-possible relaxation of `uv`, until no vertex moves by more than a thousandth of
/// `tolerance` in a round or [`ROUNDS`] are done. The first vertex is held.
fn arap(uv: &mut [[f64; 2]], tri: &[[usize; 3]], locals: &[Local], tolerance: f64) {
    let n = uv.len();
    // Cotangent weights of each triangle's edge (k, k+1), from the angle at k+2; kept
    // positive so the system stays positive definite.
    let weights: Vec<[f64; 3]> = locals
        .iter()
        .map(|l| {
            let mut w = [0.0; 3];
            for (k, slot) in w.iter_mut().enumerate() {
                let o = l.q.get((k + 2) % 3).copied().unwrap_or_default();
                let a = l.q.get(k).copied().unwrap_or_default();
                let b = l.q.get((k + 1) % 3).copied().unwrap_or_default();
                let (da, db) = ([a[0] - o[0], a[1] - o[1]], [b[0] - o[0], b[1] - o[1]]);
                let cross = (da[0] * db[1] - da[1] * db[0]).abs();
                let cot = if cross > 0.0 {
                    (da[0] * db[0] + da[1] * db[1]) / cross
                } else {
                    0.0
                };
                *slot = (0.5 * cot).max(1e-4);
            }
            w
        })
        .collect();
    // The Laplacian: neighbours with weights, and the diagonal.
    let mut nbr: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    let mut diag = vec![0.0; n];
    for (c, w) in tri.iter().zip(&weights) {
        for k in 0..3 {
            let (i, j) = (corner(c, k), corner(c, k + 1));
            let wk = w.get(k).copied().unwrap_or(0.0);
            if let Some(d) = diag.get_mut(i) {
                *d += wk;
            }
            if let Some(d) = diag.get_mut(j) {
                *d += wk;
            }
            if let Some(list) = nbr.get_mut(i) {
                list.push((j, wk));
            }
            if let Some(list) = nbr.get_mut(j) {
                list.push((i, wk));
            }
        }
    }
    let held = 0usize;
    let laplace = |x: &[f64]| -> Vec<f64> {
        (0..n)
            .map(|i| {
                if i == held {
                    return 0.0;
                }
                let xi = x.get(i).copied().unwrap_or(0.0);
                let d = diag.get(i).copied().unwrap_or(0.0);
                let off: f64 = nbr.get(i).map_or(0.0, |l| {
                    l.iter()
                        .filter(|(j, _)| *j != held)
                        .map(|&(j, w)| w * x.get(j).copied().unwrap_or(0.0))
                        .sum()
                });
                d * xi - off
            })
            .collect()
    };
    for _ in 0..ROUNDS {
        // Local step: each triangle's best rotation.
        let rot: Vec<[f64; 2]> = tri
            .iter()
            .zip(locals)
            .zip(&weights)
            .map(|((c, l), w)| {
                // S = Σ w (Δu)(Δq)ᵀ, as its entries [s00, s01, s10, s11].
                let mut s = [0.0; 4];
                for k in 0..3 {
                    let (i, j) = (corner(c, k), corner(c, k + 1));
                    let wk = w.get(k).copied().unwrap_or(0.0);
                    let du = sub2(at2(uv, i), at2(uv, j));
                    let qa = l.q.get(k).copied().unwrap_or_default();
                    let qb = l.q.get((k + 1) % 3).copied().unwrap_or_default();
                    let dq = sub2(qa, qb);
                    let [s00, s01, s10, s11] = s;
                    s = [
                        s00 + wk * du[0] * dq[0],
                        s01 + wk * du[0] * dq[1],
                        s10 + wk * du[1] * dq[0],
                        s11 + wk * du[1] * dq[1],
                    ];
                }
                let [s00, s01, s10, s11] = s;
                let angle = (s10 - s01).atan2(s00 + s11);
                [angle.cos(), angle.sin()]
            })
            .collect();
        // Global step: L u = b, the first vertex held where it is.
        let (mut rhs_u, mut rhs_v) = (vec![0.0; n], vec![0.0; n]);
        for (((c, l), w), r) in tri.iter().zip(locals).zip(&weights).zip(&rot) {
            for k in 0..3 {
                let (i, j) = (corner(c, k), corner(c, k + 1));
                let wk = w.get(k).copied().unwrap_or(0.0);
                let qa = l.q.get(k).copied().unwrap_or_default();
                let qb = l.q.get((k + 1) % 3).copied().unwrap_or_default();
                let d = sub2(qa, qb);
                let rd = [r[0] * d[0] - r[1] * d[1], r[1] * d[0] + r[0] * d[1]];
                for (rhs, value) in [(&mut rhs_u, rd[0]), (&mut rhs_v, rd[1])] {
                    if let Some(x) = rhs.get_mut(i) {
                        *x += wk * value;
                    }
                    if let Some(x) = rhs.get_mut(j) {
                        *x -= wk * value;
                    }
                }
            }
        }
        let held_at = at2(uv, held);
        let mut moved: f64 = 0.0;
        let solve = |mut b: Vec<f64>, axis: usize| -> Vec<f64> {
            // The held vertex's known value moves to the right-hand side.
            let h = held_at.get(axis).copied().unwrap_or(0.0);
            if let Some(list) = nbr.get(held) {
                for &(j, w) in list {
                    if let Some(x) = b.get_mut(j) {
                        *x += w * h;
                    }
                }
            }
            if let Some(x) = b.get_mut(held) {
                *x = 0.0;
            }
            let start: Vec<f64> = (0..n)
                .map(|i| {
                    if i == held {
                        0.0
                    } else {
                        at2(uv, i).get(axis).copied().unwrap_or(0.0)
                    }
                })
                .collect();
            let mut pre = diag.clone();
            if let Some(d) = pre.get_mut(held) {
                *d = 1.0;
            }
            cg(&laplace, &b, &pre, start, 1e-14, 4 * n + 200)
        };
        let next = [solve(rhs_u, 0), solve(rhs_v, 1)];
        for (i, p) in uv.iter_mut().enumerate() {
            if i == held {
                continue;
            }
            let q = [
                next[0].get(i).copied().unwrap_or(p[0]),
                next[1].get(i).copied().unwrap_or(p[1]),
            ];
            if !(q[0].is_finite() && q[1].is_finite()) {
                return;
            }
            moved = moved.max((q[0] - p[0]).abs().max((q[1] - p[1]).abs()));
            *p = q;
        }
        if moved < 1e-3 * tolerance {
            break;
        }
    }
}

/// Preconditioned conjugate gradients for `op(x) = b`, `op` symmetric positive semidefinite,
/// `pre` its diagonal (entries that are not positive are taken as 1), from `x`, until the
/// residual is `rel` of the right-hand side's or after `max` steps.
fn cg(
    op: &dyn Fn(&[f64]) -> Vec<f64>,
    b: &[f64],
    pre: &[f64],
    mut x: Vec<f64>,
    rel: f64,
    max: usize,
) -> Vec<f64> {
    let dot = |a: &[f64], c: &[f64]| -> f64 { a.iter().zip(c).map(|(p, q)| p * q).sum() };
    let inv: Vec<f64> = pre
        .iter()
        .map(|&d| if d > 0.0 { 1.0 / d } else { 1.0 })
        .collect();
    let ax = op(&x);
    let mut r: Vec<f64> = b.iter().zip(&ax).map(|(p, q)| p - q).collect();
    let mut z: Vec<f64> = r.iter().zip(&inv).map(|(p, q)| p * q).collect();
    let mut p = z.clone();
    let mut rz = dot(&r, &z);
    let goal = rel * rel * dot(b, b).max(1e-300);
    for _ in 0..max {
        if dot(&r, &r) <= goal {
            break;
        }
        let ap = op(&p);
        let pap = dot(&p, &ap);
        if pap.is_nan() || pap <= 0.0 {
            break;
        }
        let alpha = rz / pap;
        for (xi, pi) in x.iter_mut().zip(&p) {
            *xi += alpha * pi;
        }
        for (ri, api) in r.iter_mut().zip(&ap) {
            *ri -= alpha * api;
        }
        z = r.iter().zip(&inv).map(|(p, q)| p * q).collect();
        let rz_next = dot(&r, &z);
        let beta = rz_next / rz;
        rz = rz_next;
        for (pi, zi) in p.iter_mut().zip(&z) {
            *pi = zi + beta * *pi;
        }
    }
    x
}

/// The singular values of the map from a triangle's own plane to its flat copy.
fn singular_values(l: &Local, u0: [f64; 2], u1: [f64; 2], u2: [f64; 2]) -> (f64, f64) {
    let [q0, q1, q2] = l.q;
    let (a, b) = (sub2(q1, q0), sub2(q2, q0));
    let det = a[0] * b[1] - a[1] * b[0];
    if det.abs() < 1e-300 {
        return (1.0, 1.0);
    }
    // Q⁻¹ for Q = [a b] (columns).
    let qi = [[b[1] / det, -b[0] / det], [-a[1] / det, a[0] / det]];
    let (ua, ub) = (sub2(u1, u0), sub2(u2, u0));
    // J = U Q⁻¹ for U = [ua ub].
    let j = [
        [
            ua[0] * qi[0][0] + ub[0] * qi[1][0],
            ua[0] * qi[0][1] + ub[0] * qi[1][1],
        ],
        [
            ua[1] * qi[0][0] + ub[1] * qi[1][0],
            ua[1] * qi[0][1] + ub[1] * qi[1][1],
        ],
    ];
    let e = (j[0][0] + j[1][1]) / 2.0;
    let f = (j[0][0] - j[1][1]) / 2.0;
    let g = (j[1][0] + j[0][1]) / 2.0;
    let h = (j[1][0] - j[0][1]) / 2.0;
    let q = (e * e + h * h).sqrt();
    let r = (f * f + g * g).sqrt();
    (q + r, (q - r).abs())
}

/// A closed polyline with every point dropped that stands off the line between the points kept
/// around it by less than `tol` (Douglas–Peucker, from the point farthest from the first).
fn simplify(pts: &[[f64; 2]], tol: f64) -> Vec<[f64; 2]> {
    if pts.len() <= 3 {
        return pts.to_vec();
    }
    let first = pts.first().copied().unwrap_or_default();
    let (far, _) = pts
        .iter()
        .enumerate()
        .map(|(i, p)| (i, norm2(sub2(*p, first))))
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap_or((0, 0.0));
    let mut keep = vec![false; pts.len()];
    if let Some(k) = keep.first_mut() {
        *k = true;
    }
    if let Some(k) = keep.get_mut(far) {
        *k = true;
    }
    let mut closed: Vec<[f64; 2]> = pts.to_vec();
    closed.push(first);
    let mut stack = vec![(0usize, far), (far, pts.len())];
    while let Some((i, j)) = stack.pop() {
        if j <= i + 1 {
            continue;
        }
        let (Some(&a), Some(&b)) = (closed.get(i), closed.get(j)) else {
            continue;
        };
        let mut best = (0usize, -1.0f64);
        for k in i + 1..j {
            let d = closed.get(k).map_or(0.0, |&p| off_line(p, a, b));
            if d > best.1 {
                best = (k, d);
            }
        }
        if best.1 > tol {
            if let Some(k) = keep.get_mut(best.0) {
                *k = true;
            }
            stack.push((i, best.0));
            stack.push((best.0, j));
        }
    }
    let kept: Vec<[f64; 2]> = pts
        .iter()
        .zip(&keep)
        .filter(|(_, k)| **k)
        .map(|(p, _)| *p)
        .collect();
    if kept.len() >= 3 { kept } else { pts.to_vec() }
}

/// Distance of `p` from the segment `a`–`b`.
fn off_line(p: [f64; 2], a: [f64; 2], b: [f64; 2]) -> f64 {
    let ab = sub2(b, a);
    let ap = sub2(p, a);
    let len2 = ab[0] * ab[0] + ab[1] * ab[1];
    if len2 <= 0.0 {
        return norm2(ap);
    }
    let t = ((ap[0] * ab[0] + ap[1] * ab[1]) / len2).clamp(0.0, 1.0);
    norm2([ap[0] - t * ab[0], ap[1] - t * ab[1]])
}

fn loop_area(lp: &[[f64; 2]]) -> f64 {
    let n = lp.len();
    (0..n)
        .map(|i| {
            let a = lp.get(i).copied().unwrap_or_default();
            let b = lp.get((i + 1) % n).copied().unwrap_or_default();
            a[0] * b[1] - b[0] * a[1]
        })
        .sum::<f64>()
        / 2.0
}

fn signed_area(a: [f64; 2], b: [f64; 2], c: [f64; 2]) -> f64 {
    ((b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1])) / 2.0
}

fn at3(p: &[[f64; 3]], i: usize) -> [f64; 3] {
    p.get(i).copied().unwrap_or_default()
}
fn at2(p: &[[f64; 2]], i: usize) -> [f64; 2] {
    p.get(i).copied().unwrap_or_default()
}
fn sub3(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}
fn sub2(a: [f64; 2], b: [f64; 2]) -> [f64; 2] {
    [a[0] - b[0], a[1] - b[1]]
}
fn scale3(a: [f64; 3], s: f64) -> [f64; 3] {
    [a[0] * s, a[1] * s, a[2] * s]
}
fn dot3(a: [f64; 3], b: [f64; 3]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}
fn cross3(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
fn norm3(a: [f64; 3]) -> f64 {
    dot3(a, a).sqrt()
}
fn norm2(a: [f64; 2]) -> f64 {
    (a[0] * a[0] + a[1] * a[1]).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    /// A grid of `nu` × `nv` cells over (u, v) ∈ [0, 1]², mapped by `f`, triangles
    /// counter-clockwise seen from the side `f`'s (∂u × ∂v) points to.
    fn grid(nu: usize, nv: usize, f: impl Fn(f64, f64) -> [f64; 3]) -> (Vec<Vec3>, Vec<[u32; 3]>) {
        let mut pos = Vec::new();
        for j in 0..=nv {
            for i in 0..=nu {
                let [x, y, z] = f(i as f64 / nu as f64, j as f64 / nv as f64);
                pos.push(Vec3 { x, y, z });
            }
        }
        let id = |i: usize, j: usize| (j * (nu + 1) + i) as u32;
        let mut tris = Vec::new();
        for j in 0..nv {
            for i in 0..nu {
                tris.push([id(i, j), id(i + 1, j), id(i + 1, j + 1)]);
                tris.push([id(i, j), id(i + 1, j + 1), id(i, j + 1)]);
            }
        }
        (pos, tris)
    }

    fn one(pos: &[Vec3], tris: &[[u32; 3]], cuts: &[Vec<u32>]) -> FlatPiece {
        let tags = vec![0; tris.len()];
        let mut pieces = flatten_mesh(pos, tris, &tags, cuts, 1e-3).unwrap();
        assert_eq!(pieces.len(), 1);
        pieces.remove(0)
    }

    #[test]
    fn a_tilted_rectangle_comes_out_at_its_size() {
        let (pos, tris) = grid(8, 5, |u, v| [40.0 * u, 30.0 * v * 0.6, 30.0 * v * 0.8]);
        let p = one(&pos, &tris, &[]);
        assert_eq!(p.outer.len(), 4, "{:?}", p.outer);
        let mut e = p.extent;
        e.sort_by(f64::total_cmp);
        assert!(
            (e[0] - 30.0).abs() < 1e-6 && (e[1] - 40.0).abs() < 1e-6,
            "{e:?}"
        );
        assert!(p.max_stretch < 1e-6, "{}", p.max_stretch);
        assert!((loop_area(&p.outer) - 1200.0).abs() < 1e-6);
        assert!(p.holes.is_empty() && p.folded == 0);
    }

    #[test]
    fn a_cylinder_cut_along_its_seam_unrolls_to_its_circumference() {
        // Radius 10, height 20, all round: the grid's first and last columns are one seam.
        let (r, h, nu) = (10.0, 20.0, 64);
        let (mut pos, mut tris) = grid(nu, 6, |u, v| {
            [r * (2.0 * PI * u).cos(), r * (2.0 * PI * u).sin(), h * v]
        });
        // Weld the last column onto the first, as the mesher's shared seam nodes are.
        let col = |j: usize| (j * (nu + 1) + nu) as u32;
        let first = |j: usize| (j * (nu + 1)) as u32;
        for t in &mut tris {
            for c in t.iter_mut() {
                if let Some(j) = (0..=6).find(|&j| col(j) == *c) {
                    *c = first(j);
                }
            }
        }
        pos.truncate(pos.len());
        let seam: Vec<u32> = (0..=6).map(first).collect();
        let p = one(&pos, &tris, &[seam]);
        // The mesh's circumference: 64 chords of the circle.
        let chords = 64.0 * 2.0 * r * (PI / 64.0).sin();
        let mut e = p.extent;
        e.sort_by(f64::total_cmp);
        assert!((e[0] - h).abs() < 1e-6, "{e:?}");
        assert!((e[1] - chords).abs() < 1e-6, "{e:?} vs {chords}");
        assert!(p.max_stretch < 1e-6, "{}", p.max_stretch);
        assert_eq!(p.outer.len(), 4, "{:?}", p.outer);
    }

    #[test]
    fn without_its_seam_cut_a_tube_is_refused_as_closed_only_when_it_has_no_boundary() {
        // A closed box made of quads has no boundary: refused.
        let pos: Vec<Vec3> = [
            [0., 0., 0.],
            [1., 0., 0.],
            [1., 1., 0.],
            [0., 1., 0.],
            [0., 0., 1.],
            [1., 0., 1.],
            [1., 1., 1.],
            [0., 1., 1.],
        ]
        .iter()
        .map(|&[x, y, z]| Vec3 { x, y, z })
        .collect();
        let quads = [
            [0, 3, 2, 1],
            [4, 5, 6, 7],
            [0, 1, 5, 4],
            [1, 2, 6, 5],
            [2, 3, 7, 6],
            [3, 0, 4, 7],
        ];
        let tris: Vec<[u32; 3]> = quads
            .iter()
            .flat_map(|q| [[q[0], q[1], q[2]], [q[0], q[2], q[3]]])
            .collect();
        let tags = vec![0; tris.len()];
        let err = flatten_mesh(&pos, &tris, &tags, &[], 1e-3).unwrap_err();
        assert!(err.to_string().contains("close up"), "{err}");
    }

    #[test]
    fn a_dome_flattens_with_its_stretch_reported_and_nothing_folded() {
        // A spherical cap of radius 50 up to 40° from the pole.
        let (rad, cap) = (50.0, 40f64.to_radians());
        let (pos, tris) = grid(24, 24, |u, v| {
            let (x, y) = (2.0 * u - 1.0, 2.0 * v - 1.0);
            // A square of the cap: the angles from the pole along x and y.
            let (a, b) = (x * cap * 0.7, y * cap * 0.7);
            let d = [a.tan(), b.tan(), 1.0];
            let n = (d[0] * d[0] + d[1] * d[1] + 1.0).sqrt();
            [rad * d[0] / n, rad * d[1] / n, rad * d[2] / n]
        });
        let p = one(&pos, &tris, &[]);
        assert_eq!(p.folded, 0);
        assert!(
            p.mean_stretch > 1e-3 && p.mean_stretch < 0.05,
            "{}",
            p.mean_stretch
        );
        assert!(p.max_stretch < 0.1, "{}", p.max_stretch);
        // Area within the stretch.
        assert!((p.area_flat - p.area_3d).abs() < 0.05 * p.area_3d);
    }

    #[test]
    fn two_patches_apart_are_two_pieces_in_face_order() {
        let (mut pos, mut tris) = grid(2, 2, |u, v| [10.0 * u, 10.0 * v, 0.0]);
        let (pos2, tris2) = grid(2, 2, |u, v| [50.0 + 5.0 * u, 5.0 * v, 3.0]);
        let off = pos.len() as u32;
        pos.extend(pos2);
        let n1 = tris.len();
        tris.extend(tris2.iter().map(|t| t.map(|i| i + off)));
        let tags: Vec<u32> = (0..tris.len())
            .map(|t| if t < n1 { 7 } else { 3 })
            .collect();
        let pieces = flatten_mesh(&pos, &tris, &tags, &[], 1e-3).unwrap();
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].faces, [3]);
        assert_eq!(pieces[1].faces, [7]);
        assert!((pieces[0].area_flat - 25.0).abs() < 1e-6);
    }

    #[test]
    fn hostile_input_is_an_error_not_a_panic() {
        let pos = vec![Vec3 {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        }];
        assert!(flatten_mesh(&pos, &[[0, 1, 2]], &[0], &[], 1e-3).is_err());
        assert!(flatten_mesh(&pos, &[[0, 0, 0]], &[0], &[], 1e-3).is_err());
        assert!(flatten_mesh(&pos, &[], &[], &[], 1e-3).is_err());
        assert!(flatten_mesh(&pos, &[[0, 0, 0]], &[], &[], 1e-3).is_err());
        let nan = vec![
            Vec3 {
                x: f64::NAN,
                y: 0.0,
                z: 0.0
            };
            3
        ];
        assert!(flatten_mesh(&nan, &[[0, 1, 2]], &[0], &[], 1e-3).is_err());
        let (pos, tris) = grid(1, 1, |u, v| [u, v, 0.0]);
        assert!(flatten_mesh(&pos, &tris, &[0, 0], &[vec![99, 100]], 0.0).is_err());
        assert!(flatten_mesh(&pos, &tris, &[0, 0], &[vec![99, 100]], 1e-3).is_ok());
    }
}
