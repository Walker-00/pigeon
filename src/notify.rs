use crate::store::model::Envelope;

const MAX_LISTED: usize = 4;

pub fn desktop_new_mail(envelopes: &[Envelope]) {
    if envelopes.is_empty() {
        return;
    }

    let summary = match envelopes.len() {
        1 => format!("New mail from {}", envelopes[0].display_from()),
        n => format!("{n} new messages"),
    };

    let mut body = String::new();
    for e in envelopes.iter().take(MAX_LISTED) {
        body.push_str(&format!("{}\n  {}\n", e.display_from(), e.subject_or_placeholder()));
    }
    if envelopes.len() > MAX_LISTED {
        body.push_str(&format!("…and {} more\n", envelopes.len() - MAX_LISTED));
    }

    show(&summary, body.trim_end());
}

pub fn show(summary: &str, body: &str) {
    let summary = summary.to_string();
    let body = body.to_string();

    // A blocked or missing notification daemon must never stall the UI thread,
    // so the D-Bus round trip happens on a detached thread and failures are
    // dropped.
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary(&summary)
            .body(&body)
            .appname("pigeon")
            .icon("mail-unread")
            .timeout(notify_rust::Timeout::Milliseconds(6000))
            .show();
    });
}
