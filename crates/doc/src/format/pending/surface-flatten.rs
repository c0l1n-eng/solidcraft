//! A `SurfaceFlatten` feature (Surface › Flatten: `faces` points, optional `body` and
//! `tolerance`) lays faces flat as new planar surface bodies beside the body. Older designs have
//! no such feature and need no rewriting. The last release warns about the newer format number,
//! opens what it can read and keeps the rest; it cannot build this feature, so the flat bodies
//! are missing there.
