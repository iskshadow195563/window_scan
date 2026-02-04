# report_html.py
import os
import datetime
import json
from html import escape

def weight_to_level(weight):
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
    return escape(str(text))

def _collect_sections(results):
    sections = {"PASS": [], "FAIL": [], "ERROR": [], "UNSUPPORTED": []}
    for category, items in results.items():
        for name, res, weight in items:
            if res == "PASS":
                key = "PASS"
            elif res == "FAIL":
                key = "FAIL"
            elif isinstance(res, str) and res.startswith("ERROR"):
                key = "ERROR"
            elif res == "NOT SUPPORTED":
                key = "UNSUPPORTED"
            else:
                key = "FAIL"
            level, color = weight_to_level(weight)
            sections[key].append({
                "category": category,
                "name": name,
                "result": res,
                "weight": weight,
                "level": level,
                "color": color
            })
    return sections

def generate_html(filename, results, score):
    sections = _collect_sections(results)
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pass_items = sections["PASS"]
    fail_items = sections["FAIL"]
    err_items = sections["ERROR"]
    unsup_items = sections["UNSUPPORTED"]

    def js(obj): return json.dumps(obj, ensure_ascii=False)
    js_pass_labels, js_pass_values, js_pass_colors = js([i["name"] for i in pass_items]), js([i["weight"] for i in pass_items]), js([i["color"] for i in pass_items])
    js_fail_labels, js_fail_values, js_fail_colors = js([i["name"] for i in fail_items]), js([i["weight"] for i in fail_items]), js([i["color"] for i in fail_items])
    js_err_labels, js_err_values, js_err_colors   = js([i["name"] for i in err_items]), js([i["weight"] for i in err_items]), js([i["color"] for i in err_items])

    def build_table(items):
        if not items:
            return "<div class='meta'>無資料</div>"
        rows = []
        for item in items:
            rows.append(
                "<tr>"
                f"<td>{sanitize(item['category'])}</td>"
                f"<td>{sanitize(item['name'])}</td>"
                f"<td>{sanitize(item['result'])}</td>"
                f"<td>{sanitize(item['weight'])}</td>"
                f"<td style='color:{sanitize(item['color'])};font-weight:700'>{sanitize(item['level'])}</td>"
                "</tr>"
            )
        return (
            "<div class='table-wrap'>"
            "<table>"
            "<thead><tr><th>分類</th><th>檢查項目</th><th>結果</th><th>權重</th><th>等級</th></tr></thead>"
            "<tbody>"
            + "".join(rows) +
            "</tbody>"
            "</table>"
            "</div>"
        )

    html = f"""<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<title>GPO 掃描報告</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
body{{font-family:Inter,Arial,Helvetica,sans-serif;background:#f6f8fb;color:#111;margin:0;padding:20px}}
.container{{max-width:1200px;margin:auto}}
.header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}}
.title{{font-size:22px;font-weight:700}}
.meta{{color:#6b7280;font-size:13px}}
.stat{{font-size:28px;font-weight:700;color:#1565c0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-top:20px}}
.card{{background:#fff;border-radius:10px;padding:14px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}}
.card h3{{margin:0 0 8px;font-size:16px}}
.badge{{display:inline-block;padding:4px 8px;border-radius:8px;font-weight:700;color:#fff}}
.badge.pass{{background:#1565c0}}
.badge.fail{{background:#c62828}}
.badge.err{{background:#6b7280}}
.badge.unsupported{{background:#9e9e9e}}
.table-wrap{{max-height:220px;overflow:auto;margin-top:10px}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:6px;border-bottom:1px solid #eee;font-size:13px;text-align:left}}
th{{background:#f9fafb;font-weight:700}}
.chart{{height:220px}}
.counts{{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 10px}}
.pill{{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;background:#f3f4f6;font-size:13px}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">GPO 掃描報告</div>
      <div class="meta">產生時間: {sanitize(generated)}</div>
    </div>
    <div>
      <div class="stat">{score:.2f}%</div>
      <div class="meta">整體加權安全評分</div>
    </div>
  </div>

  <div class="grid">
"""
    html += f"""
    <div class="card">
      <h3>摘要</h3>
      <div class="counts">
        <div class="pill"><span class="badge pass">PASS</span> {len(pass_items)}</div>
        <div class="pill"><span class="badge fail">FAIL</span> {len(fail_items)}</div>
        <div class="pill"><span class="badge err">ERROR</span> {len(err_items)}</div>
        <div class="pill"><span class="badge unsupported">NOT SUPPORTED</span> {len(unsup_items)}</div>
      </div>
      <div class="meta">提示：棒狀圖顯示各項目權重（越高代表風險越高）</div>
    </div>

    <div class="card">
      <h3><span class="badge fail">FAIL</span> 需處理項目</h3>
      <div class="chart"><canvas id="failChart"></canvas></div>
      {build_table(fail_items)}
    </div>

    <div class="card">
      <h3><span class="badge err">ERROR</span> 執行錯誤</h3>
      <div class="chart"><canvas id="errChart"></canvas></div>
      {build_table(err_items)}
    </div>

    <div class="card">
      <h3><span class="badge pass">PASS</span> 通過項目</h3>
      <div class="chart"><canvas id="passChart"></canvas></div>
      {build_table(pass_items)}
    </div>

    <div class="card">
      <h3><span class="badge unsupported">NOT SUPPORTED</span> 不支援項目</h3>
      {build_table(unsup_items)}
    </div>
"""
    html += """
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
function createChart(id, labels, values, colors) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!labels || labels.length === 0) {
    ctx.font = "14px Arial";
    ctx.fillStyle = "#666";
    ctx.fillText("無資料", 10, 20);
    return;
  }
  new Chart(ctx, {
    type: 'bar',
    data: { labels: labels, datasets: [{ data: values, backgroundColor: colors }] },
    options: { 
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } },
      responsive: true,
      maintainAspectRatio: false
    }
  });
}
document.addEventListener('DOMContentLoaded', function() {
  createChart('passChart', {js_pass_labels}, {js_pass_values}, {js_pass_colors});
  createChart('failChart', {js_fail_labels}, {js_fail_values}, {js_fail_colors});
  createChart('errChart', {js_err_labels}, {js_err_values}, {js_err_colors});
});
</script>
</body>
</html>
"""

    # 寫檔
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
