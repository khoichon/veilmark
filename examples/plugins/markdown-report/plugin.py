"""Example Veilmark plugin: export a detection report as Markdown.

Install with:  veilmark plugins install examples/plugins/markdown-report
Enable with:   veilmark plugins enable markdown-report
"""


def to_markdown(report: dict) -> tuple[bytes, str]:
    v = report.get("verification") or {}
    p = report.get("payload") or {}
    lines = [
        f"# Veilmark verification report: {report['source']}",
        "",
        f"- **Detection:** {report['status']}",
        f"- **Watermark id:** `{report.get('watermark_id')}`",
        f"- **Text:** {p.get('text')!r}" if p else "- **Payload:** not recovered",
        f"- **Signature:** {v.get('signature', 'n/a')}",
        f"- **Issuer trust:** {v.get('trust', 'n/a')} {v.get('issuer_label') or ''}",
        f"- **Sync z:** {report['confidence'].get('sync_z')}",
        f"- **Generated:** {report['created']} by Veilmark {report['veilmark_version']}",
        "",
        f"> {report['disclaimer']}",
        "",
    ]
    return "\n".join(lines).encode("utf-8"), "md"


def register(api) -> None:
    api.register_exporter("markdown", to_markdown)
