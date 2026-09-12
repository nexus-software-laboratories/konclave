use serde_json::Value;

pub(crate) fn normalize_task(value: &mut Value) {
    if let Some(status) = value.get_mut("status") {
        normalize_status(status);
    }
}

pub(crate) fn normalize_task_list(value: &mut Value) {
    if let Some(tasks) = value.get_mut("tasks").and_then(Value::as_array_mut) {
        for task in tasks {
            normalize_task(task);
        }
    }
}

pub(crate) fn normalize_send_message_response(value: &mut Value) {
    if let Some(task) = value.get_mut("task") {
        normalize_task(task);
    }
}

pub(crate) fn normalize_stream_response(value: &mut Value) {
    if let Some(task) = value.get_mut("task") {
        normalize_task(task);
    }
    if let Some(status) = value
        .get_mut("statusUpdate")
        .and_then(|update| update.get_mut("status"))
    {
        normalize_status(status);
    }
}

fn normalize_status(value: &mut Value) {
    let Some(timestamp) = value
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return;
    };
    let Some(prefix) = timestamp.strip_suffix("+00:00") else {
        return;
    };
    if let Some(timestamp) = value.get_mut("timestamp") {
        *timestamp = Value::String(format!("{prefix}Z"));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn task_normalization_changes_only_the_status_timestamp() {
        let mut value = json!({
            "status": {
                "timestamp": "2026-09-12T00:00:00+00:00"
            },
            "artifacts": [{
                "parts": [{
                    "data": {
                        "timestamp": "2026-09-12T00:00:00+00:00"
                    }
                }]
            }]
        });
        normalize_task(&mut value);
        assert_eq!(value["status"]["timestamp"], "2026-09-12T00:00:00Z");
        assert_eq!(
            value["artifacts"][0]["parts"][0]["data"]["timestamp"],
            "2026-09-12T00:00:00+00:00"
        );
    }
}
