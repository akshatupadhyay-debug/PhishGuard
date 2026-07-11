import io
from flask import Flask, render_template, request, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from scanner import analyze_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        result = analyze_url(url)

    return render_template(
        "index.html",
        result=result,
        scanned_url=url
    )


@app.route("/download")
def download_report():
    url = request.args.get("url", "")
    score = request.args.get("score", "")
    verdict = request.args.get("verdict", "")
    domain = request.args.get("domain", "")
    ip = request.args.get("ip", "")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph("PhishGuard Security Report", styles["Title"])
    )
    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(f"<b>URL:</b> {url}", styles["Normal"])
    )
    elements.append(
        Paragraph(f"<b>Risk Score:</b> {score}/100", styles["Normal"])
    )
    elements.append(
        Paragraph(f"<b>Verdict:</b> {verdict}", styles["Normal"])
    )
    elements.append(
        Paragraph(f"<b>Domain:</b> {domain}", styles["Normal"])
    )
    elements.append(
        Paragraph(f"<b>IP Address:</b> {ip}", styles["Normal"])
    )

    doc.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="PhishGuard_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
