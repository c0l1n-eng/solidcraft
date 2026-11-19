//! Export Face as DXF: the outline of picked faces as a cutting file (`face.export_dxf`).

use serde_json::Value;
use solidcraft_geom::prelude::*;

use super::CommandSpec;
use crate::params::{bad, num, str_};
use crate::schema::face_dxf::{FaceDxfParams, FaceDxfPiece, FaceDxfResult};
use crate::schema::{TypedContract, output_schema_for};
use crate::{EngineError, Result, Session};

const FACE_DXF_CONTRACT: TypedContract<FaceDxfParams> = TypedContract::new();

pub static COMMANDS: &[CommandSpec] = &[CommandSpec::new("face.export_dxf", "Export Face as DXF", crate::checked!("face.export_dxf", export))
    .icon("dxf")
    .noundo()
    .read_only()
    .contract(&FACE_DXF_CONTRACT)
    .output(output_schema_for::<FaceDxfResult>)
    .params("faces: [[x,y,z]] (points on the faces, one body); body?; path?: file to write (else the DXF text is returned); tolerance?: mm (how far lines may stand off a curved edge; default from the body's size) → DXF (AutoCAD 2000, mm): outer contours on OUTLINE, holes on CUT. Flat faces on one plane keep exact lines and arcs; curved faces are laid flat first (as surface.flatten) and their stretch is reported")];

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let cmd = "face.export_dxf";
    let points: Vec<solidcore_record::Vec3> =
        p.get("faces").and_then(Value::as_array).map(|a| a.iter().filter_map(crate::params::vec3).collect()).unwrap_or_default();
    if points.is_empty() || points.len() > 1000 {
        return Err(bad(cmd, "`faces` must list 1 to 1000 points on the faces to export"));
    }
    let tolerance = match p.get("tolerance").filter(|v| !v.is_null()) {
        None => 0.0,
        Some(_) => num(p, "tolerance").filter(|t| t.is_finite() && (0.0..=10.0).contains(t)).ok_or_else(|| bad(cmd, "`tolerance` must be 0 to 10 mm"))?,
    };
    let path = match p.get("path").filter(|v| !v.is_null()) {
        None => None,
        Some(v) => Some(v.as_str().filter(|t| !t.trim().is_empty()).ok_or_else(|| bad(cmd, "`path` must be a file name"))?),
    };
    let world = s.world_state()?;
    let first = points.first().copied().unwrap_or_default();
    let body = match str_(p, "body") {
        Some(name) => world.body(name).ok_or_else(|| bad(cmd, format!("no body `{name}`")))?,
        None => world
            .bodies
            .iter()
            .find(|b| solidcraft_doc::appearance::face_index_at(b, first).is_some())
            .ok_or_else(|| bad(cmd, format!("no face at {:?}", [first.x, first.y, first.z])))?,
    };
    let mut faces = Vec::new();
    for pt in &points {
        let f = solidcraft_doc::appearance::face_index_at(body, *pt)
            .ok_or_else(|| bad(cmd, format!("no face of `{}` at {:?}", body.name, [pt.x, pt.y, pt.z])))?;
        if !faces.contains(&f) {
            faces.push(f);
        }
    }
    let outline = solidcraft_kernel::face_outline(&body.body, &faces, tolerance).map_err(|e| bad(cmd, e.to_string()))?;
    let layers = [solidcraft_io::DxfLayer::new("OUTLINE", 7), solidcraft_io::DxfLayer::new("CUT", 1)];
    let mut entities = Vec::new();
    for r in &outline.regions {
        for h in &r.holes {
            entities.push(solidcraft_io::DxfEntity { layer: "CUT".into(), shape: solidcraft_io::loop_lwpolyline(h) });
        }
        entities.push(solidcraft_io::DxfEntity { layer: "OUTLINE".into(), shape: solidcraft_io::loop_lwpolyline(&r.outer) });
    }
    if entities.is_empty() {
        return Err(bad(cmd, "the faces have no outline to write"));
    }
    let text = solidcraft_io::write_dxf_drawing_units(&layers, &entities, 4).map_err(|e| EngineError::Other(e.to_string()))?;
    let pieces: Vec<FaceDxfPiece> = outline
        .pieces
        .iter()
        .map(|i| FaceDxfPiece { max_stretch_pct: i.max_stretch * 100.0, mean_stretch_pct: i.mean_stretch * 100.0, folded: i.folded > 0 })
        .collect();
    let worst = pieces.iter().map(|q| q.max_stretch_pct).fold(0.0, f64::max);
    let warning = if pieces.iter().any(|q| q.folded) {
        Some("the faces were laid flat, and a piece overlaps itself: export fewer faces at a time".to_string())
    } else if worst > 1.0 {
        Some(format!("the faces were laid flat and stretched up to {worst:.1} %: they cannot lie flat exactly"))
    } else {
        None
    };
    let mut reply = FaceDxfResult {
        path: None,
        dxf: None,
        exact: outline.plane.is_some(),
        contours: entities.len(),
        pieces,
        warning,
        param_warnings: Vec::new(),
    };
    match path {
        Some(path) => {
            solidcraft_io::vfs::write(path, text.as_bytes()).map_err(|e| EngineError::Other(format!("{path}: {e}")))?;
            reply.path = Some(path.to_string());
        }
        None => reply.dxf = Some(text),
    }
    serde_json::to_value(reply).map_err(|e| EngineError::Other(e.to_string()))
}
