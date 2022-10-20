// class IncrementalSource(IntEnum):
//     MUTATION = 0
//     MOUSEMOVE = 1
//     MOUSEINTERACTION = 2
//     SCROLL = 3
//     VIEWPORTRESIZE = 4
//     INPUT = 5
//     TOUCHMOVE = 6
//     MEDIAINTERACTION = 7
//     STYLESHEETRULE = 8
//     CANVASMUTATION = 9
//     FONT = 10
//     LOG = 11
//     DRAG = 12
//     STYLEDECLARATION = 13

use std::collections::HashMap;

use serde::de::Error as DError;
use serde::{Deserialize, Serialize};
use serde_json::{Error, Value};

pub fn parse(bytes: &[u8]) -> Result<Vec<Event>, Error> {
    let node: Vec<Event> = serde_json::from_slice(bytes)?;
    return Ok(node);
}

pub fn write(rrweb: Vec<Event>) -> Result<Vec<u8>, Error> {
    return serde_json::to_vec(&rrweb);
}

pub fn mask_pii(mut events: Vec<Event>) -> Vec<Event> {
    for event in &mut events {
        match &mut event.variant {
            EventVariant::T2(variant) => recurse_snapshot_node(&mut variant.data.node),
            EventVariant::T3(variant) => {}
            EventVariant::T5(variant) => {}
            _ => {}
        }
    }
    return events;
}

fn recurse_snapshot_node(variant: &mut NodeVariant) {
    match variant {
        NodeVariant::T0(node_variant) => {
            for node in &mut node_variant.child_nodes {
                recurse_snapshot_node(node)
            }
        }
        NodeVariant::T2(element) => recurse_element(element),
        NodeVariant::T3(node_variant) => {
            node_variant.strip_pii();
        }
        _ => {}
    }
}

fn recurse_element(element: &mut ElementNode) {
    match element.tag_name.as_str() {
        "script" | "style" => {}
        "img" => {
            let attrs = &mut element.attributes;
            attrs.insert("src".to_string(), "#".to_string());
        }
        _ => {
            for variant in &mut element.child_nodes {
                recurse_snapshot_node(variant)
            }
        }
    }
}

fn strip_pii(value: &str) -> &str {
    return value;
}

/// Event Type Parser
///
/// Events have an internally tagged variant on their "type" field. The type must be one of seven
/// values. There are no default types for this variation. Because the "type" field's values are
/// integers we must define custom serialization and deserailization behavior.

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    #[serde(flatten)]
    variant: EventVariant,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum EventVariant {
    // DOMContentLoadedEvent,
    // LoadEvent,
    T2(FullSnapshotEvent),
    T3(IncrementalSnapshotEvent),
    T4(MetaEvent),
    T5(CustomEvent),
    // PluginEvent,  No examples :O
}

impl<'de> serde::Deserialize<'de> for EventVariant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;

        match value.get("type") {
            Some(val) => match Value::as_u64(val) {
                Some(v) => match v {
                    2 => match FullSnapshotEvent::deserialize(value) {
                        Ok(event) => Ok(EventVariant::T2(event)),
                        Err(_) => Err(DError::custom("could not parse snapshot event")),
                    },
                    3 => match IncrementalSnapshotEvent::deserialize(value) {
                        Ok(event) => Ok(EventVariant::T3(event)),
                        Err(_) => Err(DError::custom("could not parse incremental snapshot event")),
                    },
                    4 => match MetaEvent::deserialize(value) {
                        Ok(event) => Ok(EventVariant::T4(event)),
                        Err(_) => Err(DError::custom("could not parse meta event")),
                    },
                    5 => match CustomEvent::deserialize(value) {
                        Ok(event) => Ok(EventVariant::T5(event)),
                        Err(_) => Err(DError::custom("could not parse custom event")),
                    },
                    _ => return Err(DError::custom("invalid type value")),
                },
                None => return Err(DError::custom("type field must be an integer")),
            },
            None => return Err(DError::missing_field("type")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FullSnapshotEvent {
    #[serde(rename = "type")]
    ty: u8,
    timestamp: u64,
    data: FullSnapshotEventData,
}

#[derive(Debug, Serialize, Deserialize)]
struct FullSnapshotEventData {
    node: NodeVariant,
    #[serde(rename = "initialOffset")]
    initial_offset: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncrementalSnapshotEvent {
    #[serde(rename = "type")]
    ty: u8,
    timestamp: u64,
    data: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct MetaEvent {
    #[serde(rename = "type")]
    ty: u8,
    timestamp: u64,
    data: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomEvent {
    #[serde(rename = "type")]
    ty: u8,
    timestamp: f64,
    data: CustomEventData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum CustomEventData {
    #[serde(rename = "breadcrumb")]
    Breadcrumb(Breadcrumb),
    #[serde(rename = "performanceSpan")]
    PerformanceSpan(PerformanceSpan),
}

#[derive(Debug, Serialize, Deserialize)]
struct Breadcrumb {
    tag: String,
    payload: BreadcrumbPayload,
}

#[derive(Debug, Serialize, Deserialize)]
struct BreadcrumbPayload {
    #[serde(rename = "type")]
    ty: String,
    timestamp: f64,
    category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceSpan {
    tag: String,
    payload: PerformanceSpanPayload,
}

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceSpanPayload {
    op: String,
    description: String, // TODO: needs to be pii stripped (uri params)
    #[serde(rename = "startTimestamp")]
    start_timestamp: f64,
    #[serde(rename = "endTimestamp")]
    end_timestamp: f64,
    data: Value,
}

/// Node Type Parser
///
/// Nodes have an internally tagged variant on their "type" field. The type must be one of six
/// values.  There are no default types for this variation. Because the "type" field's values are
/// integers we must define custom serialization and deserailization behavior.

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum NodeVariant {
    T0(DocumentNode),
    T1(DocumentTypeNode),
    T2(ElementNode),
    T3(TextNode), // types 3 (text), 4 (cdata), 5 (comment)
}

impl<'de> serde::Deserialize<'de> for NodeVariant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(d)?;

        match value.get("type") {
            Some(val) => match Value::as_u64(val) {
                Some(v) => match v {
                    0 => match DocumentNode::deserialize(value) {
                        Ok(document) => Ok(NodeVariant::T0(document)),
                        Err(_) => Err(DError::custom("could not parse document object.")),
                    },
                    1 => match DocumentTypeNode::deserialize(value) {
                        Ok(document_type) => Ok(NodeVariant::T1(document_type)),
                        Err(_) => Err(DError::custom("could not parse document-type object")),
                    },
                    2 => match ElementNode::deserialize(value) {
                        Ok(element) => Ok(NodeVariant::T2(element)),
                        Err(_) => Err(DError::custom("could not parse element object")),
                    },
                    3 | 4 | 5 => match TextNode::deserialize(value) {
                        Ok(text) => Ok(NodeVariant::T3(text)),
                        Err(_) => Err(DError::custom("could not parse text object")),
                    },
                    _ => return Err(DError::custom("invalid type value")),
                },
                None => return Err(DError::custom("type field must be an integer")),
            },
            None => return Err(DError::missing_field("type")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DocumentNode {
    id: u32,
    #[serde(rename = "type")]
    ty: u8,
    #[serde(rename = "childNodes")]
    child_nodes: Vec<NodeVariant>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DocumentTypeNode {
    id: u32,
    #[serde(rename = "type")]
    ty: u8,
    #[serde(rename = "publicId")]
    public_id: String,
    #[serde(rename = "systemId")]
    system_id: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ElementNode {
    id: u32,
    #[serde(rename = "type")]
    ty: u8,
    attributes: HashMap<String, String>,
    #[serde(rename = "tagName")]
    tag_name: String,
    #[serde(rename = "childNodes")]
    child_nodes: Vec<NodeVariant>,
    #[serde(rename = "isSVG", skip_serializing_if = "Option::is_none")]
    is_svg: Option<bool>,
    #[serde(rename = "needBlock", skip_serializing_if = "Option::is_none")]
    need_block: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TextNode {
    id: u32,
    #[serde(rename = "type")]
    ty: u8,
    #[serde(rename = "textContent")]
    text_content: String,
    #[serde(rename = "isStyle", skip_serializing_if = "Option::is_none")]
    is_style: Option<bool>,
}

impl TextNode {
    fn strip_pii(&mut self) {
        self.text_content = strip_pii(&self.text_content).to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::recording;
    use assert_json_diff::assert_json_eq;
    use serde_json::Value;

    // RRWeb Payload Coverage

    #[test]
    fn test_rrweb_parsing() {
        let payload = include_bytes!("../tests/fixtures/rrweb.json");

        let input_parsed = recording::parse(payload).unwrap();
        let input_raw: Value = serde_json::from_slice(payload).unwrap();
        assert_json_eq!(input_parsed, input_raw)
    }

    // Node coverage
    #[test]
    fn test_rrweb_node_2_parsing() {
        let payload = include_bytes!("../tests/fixtures/rrweb-node-2.json");

        let input_parsed: recording::NodeVariant = serde_json::from_slice(payload).unwrap();
        let input_raw: Value = serde_json::from_slice(payload).unwrap();
        assert_json_eq!(input_parsed, input_raw)
    }

    #[test]
    fn test_rrweb_node_2_style_parsing() {
        let payload = include_bytes!("../tests/fixtures/rrweb-node-2-style.json");

        let input_parsed: recording::NodeVariant = serde_json::from_slice(payload).unwrap();
        let input_raw: Value = serde_json::from_slice(payload).unwrap();
        assert_json_eq!(input_parsed, input_raw)
    }

    // Event coverage

    #[test]
    fn test_rrweb_event_3_parsing() {
        let payload = include_bytes!("../tests/fixtures/rrweb-event-3.json");

        let input_parsed: recording::Event = serde_json::from_slice(payload).unwrap();
        let input_raw: Value = serde_json::from_slice(payload).unwrap();
        assert_json_eq!(input_parsed, input_raw)
    }

    #[test]
    fn test_rrweb_event_5_parsing() {
        let payload = include_bytes!("../tests/fixtures/rrweb-event-5.json");

        let input_parsed: recording::Event = serde_json::from_slice(payload).unwrap();
        let input_raw: Value = serde_json::from_slice(payload).unwrap();
        assert_json_eq!(input_parsed, input_raw)
    }
}
