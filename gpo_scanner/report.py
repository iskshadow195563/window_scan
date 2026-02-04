# report.py
import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

# ---------- TXT / PDF 保留原有功能 ----------
def generate_txt(filename, results, score):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"掃描報告 - {datetime.datetime.now()}\n")
        f.write("="*80 + "\n")
        f.write(f"整體加權安全評分: {score:.2f}%\n\n")
        for category, items in results.items():
            f.write(f"[{category}]\n")
            for name, res, weight in items:
                f.write(f"{name} | 結果: {res} | 權重: {weight}\n")
            f.write("\n")

def generate_pdf(filename, results, score):
    # 需要 reportlab，若未安裝會拋出例外，由呼叫端處理
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("GPO 掃描報告", styles["Title"]))
    story.append(Paragraph(f"產生時間: {datetime.datetime.now()}", styles["Normal"]))
    story.append(Spacer(1,12))
    story.append(Paragraph(f"整體加權安全評分: {score:.2f}%", styles["Heading2"]))
    story.append(Spacer(1,12))
    for category, items in results.items():
        story.append(Paragraph(category, styles["Heading3"]))
        data = [["檢查項目", "結果", "權重"]]
        for name, res, weight in items:
            data.append([name, res, str(weight)])
        tbl = Table(data, colWidths=[300,100,60])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1,12))
    doc.build(story)

# ---------- HTML5 檢視器（含 Chart.js 棒形圖） ----------
def weight_to_level(weight):
    """將權重轉為威脅等級與顏色"""
    if weight >= 5:
        return "Critical", "#c62828"
    if weight == 4:
        return "High", "#ef6c00"
    if weight == 3:
        return "Medium", "#f9a825"
    if weight == 2:
        return "Low", "#2e7d32"
    return "Info", "#1565c0"

def sanitize(text):
    """簡單 HTML escape（可視需要擴充）"""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

def generate_html(filename, results, score):
    """
    產生一個 HTML5 檔案，內含：
    - 檢查結果表格（按分類）
    - 使用 Chart.js 的棒形圖，列出所有 FAIL/ERROR 項目與其權重/威脅等級
    - 簡單 CSS 美化
    """
    # 收集需要在圖表中顯示的項目（只列 FAIL / ERROR）
    chart_labels = []
    chart_values = []
    chart_colors = []
    chart_levels = []
    table_rows_html = []

    # 也把所有項目列在表格中（包含 PASS）
    for category, items in results.items():
        table_rows_html.append(f"<tr class='category-row'><td colspan='4'><strong>{sanitize(category)}</strong></td></tr>")
        for name, res, weight in items:
            level, color = weight_to_level(weight)
            # 若 FAIL 或 ERROR，加入圖表
            if res == "FAIL" or (isinstance(res, str) and res.startswith("ERROR")):
                chart_labels.append(sanitize(name))
                chart_values.append(weight)
                chart_colors.append(color)
                chart_levels.append(level)
            # 表格列
            table_rows_html.append(
                "<tr>"
                f"<td>{sanitize(name)}</td>"
                f"<td>{sanitize(res)}</td>"
                f"<td>{weight}</td>"
                f"<td style='color:{color};font-weight:600'>{level}</td>"
                "</tr>"
            )

    # HTML 模板（使用 Chart.js CDN）
    html = f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPO 掃描報告</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  body{{font-family:Inter,Arial,Helvetica,sans-serif;margin:0;background:#f7f9fb;color:#222}}
  .container{{max-width:1100px;margin:24px auto;padding:20px;background:#fff;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.06)}}
  h1{{margin:0 0 8px;font-size:22px}}
  .meta{{color:#666;margin-bottom:16px}}
  .score-box{{display:flex;align-items:center;gap:16px;margin-bottom:18px}}
  .score-value{{font-size:28px;font-weight:700;color:#1565c0}}
  .chart-wrap{{width:100%;max-width:900px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;margin-top:12px}}
  th,td{{padding:10px;border-bottom:1px solid #eee;text-align:left}}
  th{{background:#fafafa;color:#333}}
  tr.category-row td{{background:#f1f5f9;font-weight:700}}
  .legend{{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}}
  .legend-item{{display:flex;align-items:center;gap:6px;padding:6px 8px;border-radius:6px;background:#fff;border:1px solid #eee}}
  .btn{{display:inline-block;padding:8px 12px;background:#1976d2;color:#fff;border-radius:6px;text-decoration:none}}
  .note{{margin-top:12px;color:#555;font-size:13px}}
  @media (max-width:700px){{
    .container{{padding:12px}}
    .chart-wrap{{max-width:100%}}
  }}
</style>
</head>
<body>
<div class="container">
  <h1>GPO 掃描報告</h1>
  <div class="meta">產生時間: {datetime.datetime.now()} &nbsp;|&nbsp; 整體加權安全評分: <strong>{score:.2f}%</strong></div>

  <div class="score-box">
    <div>
      <div class="score-value">{score:.2f}%</div>
      <div class="note">分數越高代表符合越多高權重檢查</div>
    </div>
    <div style="flex:1">
      <div class="chart-wrap">
        <canvas id="vulnChart" width="900" height="300"></canvas>
      </div>
      <div class="legend" id="legend"></div>
    </div>
  </div>

  <h2>檢查明細</h2>
  <table>
    <thead><tr><th>檢查項目</th><th>結果</th><th>權重</th><th>威脅等級</th></tr></thead>
    <tbody>
      {''.join(table_rows_html)}
    </tbody>
  </table>

  <div class="note">
    <strong>說明：</strong>圖表列出掃描中所有 <em>FAIL / ERROR</em> 的檢查項目，並以權重顯示其相對重要性。威脅等級由權重自動對應（5=Critical,4=High,3=Medium,2=Low,1=Info）。
  </div>
</div>

<!-- Chart.js CDN -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
  const labels = {chart_labels};
  const data = {{
    labels: labels,
    datasets: [{{
      label: '權重 (重要性)',
      data: {chart_values},
      backgroundColor: {chart_colors},
      borderColor: {chart_colors},
      borderWidth: 1
    }}]
  }};

  const config = {{
    type: 'bar',
    data: data,
    options: {{
      indexAxis: 'y',
      scales: {{
        x: {{
          beginAtZero: true,
          ticks: {{ stepSize: 1 }}
        }}
      }},
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: function(context) {{
              const idx = context.dataIndex;
              const level = {chart_levels}[idx] || '';
              return '權重: ' + context.parsed.x + '  等級: ' + level;
            }}
          }}
        }}
      }},
      responsive: true,
      maintainAspectRatio: false
    }}
  }};

  const ctx = document.getElementById('vulnChart').getContext('2d');
  const vulnChart = new Chart(ctx, config);

  // 建立圖例
  const legendEl = document.getElementById('legend');
  const levels = {{}};
  {generate_legend_js := ""}
</script>
</body>
</html>
"""

    # 把 Python list 轉成 JS 陣列字串（已 escape）
    # chart_labels, chart_values, chart_colors, chart_levels 需要 JSON-like 字串
    import json
    html = html.replace("{chart_labels}", json.dumps(chart_labels, ensure_ascii=False))
    html = html.replace("{chart_values}", json.dumps(chart_values))
    html = html.replace("{chart_colors}", json.dumps(chart_colors))
    html = html.replace("{chart_levels}", json.dumps(chart_levels, ensure_ascii=False))

    # 寫檔
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
