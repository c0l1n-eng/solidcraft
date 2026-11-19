//! Contracts and result types for the command in `cmd/face_dxf.rs`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::Point3;

/// Write the outline of faces as a DXF (AutoCAD 2000, mm), for a laser, waterjet or plotter.
/// Flat faces on one plane keep their exact edges: lines, arcs and circles, other edges as short
/// lines; several such faces are one outline where they meet. Curved faces, or flat ones on
/// different planes, are laid flat first (as `surface.flatten`), each connected patch a piece of
/// straight sides, with how far it stretched in `pieces`. Outer contours are on layer OUTLINE,
/// holes on layer CUT, holes first. Changes nothing in the design.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct FaceDxfParams {
    /// Points on the faces, in mm: 1 to 1000, all on one body.
    #[schemars(length(min = 1, max = 1000))]
    pub faces: Vec<Point3>,
    /// The body the faces are on, by name. Default: the body at the first point.
    #[serde(default)]
    pub body: Option<String>,
    /// The file to write. Default: none, and the DXF text is returned.
    #[serde(default)]
    pub path: Option<String>,
    /// How far a chain of short lines may stand off a curved edge, in mm (0 to 10; 0, the
    /// default, picks one from the body's size).
    #[serde(default)]
    pub tolerance: Option<f64>,
}

/// One flattened piece of a [`FaceDxfResult`]: how far it stretched to lie flat.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FaceDxfPiece {
    /// The largest stretch at any point, in percent.
    pub max_stretch_pct: f64,
    /// The area-weighted mean stretch, in percent.
    pub mean_stretch_pct: f64,
    /// True when the piece overlaps itself.
    pub folded: bool,
}

/// What `face.export_dxf` returns.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FaceDxfResult {
    /// The file written, when `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The DXF text, when no `path` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dxf: Option<String>,
    /// True when the faces were flat on one plane and their edges are exact.
    pub exact: bool,
    /// Closed contours written (outlines and holes).
    pub contours: usize,
    /// The flattened pieces, when the faces were laid flat.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pieces: Vec<FaceDxfPiece>,
    /// What the user should know: the faces were laid flat and stretched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// In the warn parameter-check mode: what the call's parameters got wrong.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::FaceDxfParams;
    use crate::Session;
    use crate::schema::input_schema_for;
    use crate::schema::tests::assert_keys;

    fn run(s: &mut Session, c: &str, p: Value) -> Value {
        s.execute(c, &p).unwrap_or_else(|e| panic!("{c}: {e}"))
    }

    #[test]
    fn schemas_and_the_key_check_agree() {
        assert_keys(input_schema_for::<FaceDxfParams>(), &["body", "faces", "path", "tolerance"]);
    }

    /// A plate's top with a hole: one outline of four lines on OUTLINE and one circle on CUT,
    /// exact; a can's side laid flat; bad calls refused, the design unchanged.
    #[test]
    fn a_face_is_written_as_a_dxf() {
        let mut s = Session::default();
        run(&mut s, "solid.box", json!({"length": 40, "width": 30, "height": 5, "body_name": "Plate"}));
        run(&mut s, "solid.cylinder", json!({"radius": 4, "height": 7, "base": [20, 15, -1], "operation": "cut", "targets": ["Plate"]}));
        let r = run(&mut s, "face.export_dxf", json!({"faces": [[2, 2, 5]]}));
        assert_eq!(r["exact"], json!(true), "{r}");
        assert_eq!(r["contours"], json!(2), "{r}");
        let dxf = r["dxf"].as_str().unwrap();
        assert!(dxf.contains("LWPOLYLINE") && dxf.contains("OUTLINE") && dxf.contains("CUT"), "{dxf}");
        let read = solidcraft_io::read_dxf(dxf).unwrap();
        assert!(!read.is_empty());
        run(&mut s, "solid.cylinder", json!({"radius": 10, "height": 20, "base": [0, 60, 0], "body_name": "Can"}));
        let r = run(&mut s, "face.export_dxf", json!({"faces": [[10, 60, 10]], "body": "Can"}));
        assert_eq!(r["exact"], json!(false), "{r}");
        assert_eq!(r["pieces"].as_array().map(Vec::len), Some(1), "{r}");
        let before = s.doc.to_json();
        let undo = s.undo.len();
        for bad in [
            json!({"faces": []}),
            json!({"faces": [[500, 500, 500]]}),
            json!({"faces": [[2, 2, 5]], "body": "Nope"}),
            json!({"faces": [[2, 2, 5]], "tolerance": -1}),
        ] {
            assert!(s.execute("face.export_dxf", &bad).is_err(), "{bad}");
        }
        assert_eq!((s.doc.to_json(), s.undo.len()), (before, undo));
    }
}
