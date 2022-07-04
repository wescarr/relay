initSidebarItems({"constant":[["VALID_PLATFORMS",""]],"enum":[["Context","A context describes environment info (e.g. device, os or browser)."],["DebugImage","A debug information file (debug image)."],["EventType","The type of an event."],["Level","Severity level of an event or breadcrumb."],["SecurityReportType",""],["SessionErrored","Contains information about errored sessions. See [`SessionLike`]."],["SessionStatus","The type of session event we’re dealing with."],["SpanStatus","Trace status."],["ThreadId","Represents a thread id."],["TransactionSource","Describes how the name of the transaction was determined."]],"fn":[["datetime_to_timestamp",""],["event_json_schema","Get the event schema as JSON schema. The return type is serde-serializable."],["validate_environment","Given a string checks if the environment name is generally valid."],["validate_release","Given a string checks if the release is generally valid."]],"struct":[["Addr","An address"],["AppContext","Application information."],["AppleDebugImage","Legacy apple debug images (MachO)."],["Breadcrumb","The Breadcrumbs Interface specifies a series of application events, or “breadcrumbs”, that occurred before an event."],["Breakdowns","A map of breakdowns. Breakdowns may be available on any event type. A breakdown are product-defined measurement values generated by the client, or materialized during ingestion. For example, for transactions, we may emit span operation breakdowns based on the attached span data."],["BrowserContext","Web browser information."],["CError","POSIX signal with optional extended data."],["ClientReport",""],["ClientSdkInfo","The SDK Interface describes the Sentry SDK and its configuration used to capture and transmit an event."],["ClientSdkPackage","An installed and loaded package as part of the Sentry SDK."],["CodeId",""],["ContextInner",""],["Contexts","The Contexts Interface provides additional context data. Typically, this is data related to the current user and the environment. For example, the device or application version. Its canonical name is `contexts`."],["Cookies","A map holding cookies."],["Csp","Models the content of a CSP report."],["DebugId",""],["DebugMeta","Debugging and processing meta information."],["DeviceContext","Device information."],["DiscardedEvent",""],["Event","The sentry v7 event structure."],["EventId","Wrapper around a UUID with slightly different formatting."],["EventProcessingError","An event processing error."],["Exception","A single exception."],["ExpectCt","Expect CT security report sent by user agent (browser)."],["ExpectStaple","Represents an Expect Staple security report."],["ExtraValue",""],["Fingerprint","A fingerprint value."],["Frame","Holds information about a single stacktrace frame."],["FrameData","Additional frame data information."],["FrameVars","Frame local variables."],["Geo","Geographical location of the end user or device."],["GpuContext","GPU information."],["GroupingConfig","The grouping config that should be used for grouping this event."],["HeaderName","A “into-string” type that normalizes header names."],["HeaderValue","A “into-string” type that normalizes header values."],["Headers","A map holding headers."],["Hpkp","Schema as defined in RFC7469, Section 3"],["InvalidRegVal","Raised if a register value can’t be parsed."],["IpAddr","An ip address."],["JsonLenientString","A “into-string” type of value. All non-string values are serialized as JSON."],["LenientString","A “into-string” type of value. Emulates an invocation of `str(x)` in Python"],["LogEntry","A log entry message."],["MachException","Mach exception information."],["Measurement","An individual observed measurement."],["Measurements","A map of observed measurement values."],["Mechanism","The mechanism by which an exception was generated and handled."],["MechanismMeta","Operating system or runtime meta information to an exception mechanism."],["Message",""],["Metrics","Metrics captured during event ingestion and processing."],["NativeDebugImage","A generic (new-style) native platform debug information file."],["NativeImagePath","A type for strings that are generally paths, might contain system user names, but still cannot be stripped liberally because it would break processing for certain platforms."],["OsContext","Operating system information."],["PairList","A mixture of a hashmap and an array."],["ParseEventTypeError","An error used when parsing `EventType`."],["ParseLevelError","An error used when parsing `Level`."],["ParseSessionStatusError","An error used when parsing `SessionStatus`."],["PosixSignal","POSIX signal with optional extended data."],["Query","A map holding query string pairs."],["RawStacktrace","A stack trace of a single thread."],["RegVal","A register value."],["RelayInfo","The Relay Interface describes a Sentry Relay and its configuration used to process an event during ingest."],["Request","Http request information."],["RuntimeContext","Runtime information."],["SampleRate",""],["SessionAggregateItem",""],["SessionAggregates",""],["SessionAttributes","Additional attributes for Sessions."],["SessionUpdate",""],["Span",""],["SpanId","A 16-character hex string as described in the W3C trace context spec."],["Stacktrace",""],["SystemSdkInfo","Holds information about the system SDK."],["TagEntry",""],["Tags","Manual key/value tag pairs."],["TemplateInfo","Template debug information."],["Thread","A process thread of an event."],["Timestamp",""],["TraceContext","Trace context"],["TraceId","A 32-character hex string as described in the W3C trace context spec."],["TransactionInfo","Additional information about the name of the transaction."],["User","Information about the user who triggered an event."],["UserReport","User feedback for an event as sent by the client to the userfeedback/userreport endpoint."],["Values","A array like wrapper used in various places."]],"trait":[["AsPair","A trait to abstract over pairs."],["SessionLike","Common interface for [`SessionUpdate`] and [`SessionAggregateItem`]."]],"type":[["OperationType","Operation type such as `db.statement` for database queries or `http` for external HTTP calls. Tries to follow OpenCensus/OpenTracing’s span types."]]});