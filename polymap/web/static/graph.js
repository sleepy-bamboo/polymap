async function loadJSON(url) {
  const r = await fetch(url);
  return await r.json();
}

function edgePermissions(edge) {
  const perms = edge.data("permissions");
  return Array.isArray(perms) ? perms : [];
}

function edgeVerdicts(edge) {
  const perms = edgePermissions(edge);
  const set = new Set(perms.map(p => p.verdict));
  return Array.from(set);
}

function hasVerdict(edge, verdict) {
  const perms = edgePermissions(edge);
  return perms.some(p => p.verdict === verdict);
}

function applyFilters(cy) {
  const showCritical = document.getElementById("showCritical").checked;
  const showHighRisk = document.getElementById("showHighRisk").checked;
  const showAllowed = document.getElementById("showAllowed").checked;
  const showAmbiguous = document.getElementById("showAmbiguous").checked;
  const showDenied = document.getElementById("showDenied").checked;

  cy.nodes().forEach(n => {
    const t = n.data("type");
    if (t !== "s3_bucket") { n.style("display", "element"); return; }
    const critical = !!n.data("critical");
    const highRisk = !!n.data("high_risk");
    const ok = (critical && showCritical) || (highRisk && showHighRisk);
    n.style("display", ok ? "element" : "none");
  });

  cy.edges().forEach(e => {
    const ok =
      (showAllowed && hasVerdict(e, "ALLOWED")) ||
      (showAmbiguous && hasVerdict(e, "AMBIGUOUS")) ||
      (showDenied && hasVerdict(e, "DENIED"));
    e.style("display", ok ? "element" : "none");
  });
}

function renderTopPaths(report) {
  const ol = document.getElementById("topPaths");
  ol.innerHTML = "";
  (report.top_paths || []).slice(0, 20).forEach(item => {
    const li = document.createElement("li");
    li.textContent = `${item.score}: ${item.path.map(x => x.replace("s3::", "")).join(" → ")}`;
    ol.appendChild(li);
  });

  const notes = document.getElementById("notes");
  notes.innerHTML = "";
  (report.notes || []).forEach(n => {
    const p = document.createElement("p");
    p.textContent = n;
    notes.appendChild(p);
  });
}

(async function main() {
  try {
    if (typeof cytoscape === "undefined") {
      throw new Error("Cytoscape failed to load.");
    }

    const graph = await loadJSON("/graph.json");
    const report = await loadJSON("/report.json").catch(() => ({}));
    renderTopPaths(report);

    const edgeList = graph.edges || graph.links || [];
    const elements = {
      nodes: graph.nodes.map(n => ({ data: n })),
      edges: edgeList.map(e => ({ data: { id: `${e.source}->${e.target}`, ...e } })),
    };
    elements.edges.forEach(e => {
      const perms = (e.data.permissions || []);
      const verdicts = Array.from(new Set(perms.map(p => p.verdict))).sort();
      if (verdicts.length) e.data.label = verdicts.join(",");
    });
    const cy = cytoscape({
      container: document.getElementById("cy"),
      elements,
      layout: { name: "cose" },
      style: [
        { selector: "node", style: { "label": "data(label)", "text-wrap": "wrap", "text-max-width": 140, "background-color": "data(color)", "width": "mapData(weight, 1, 3, 28, 42)", "height": "mapData(weight, 1, 3, 28, 42)" } },
        { selector: 'node[type="entrypoint"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="role"]', style: { "shape": "rectangle" } },
        { selector: 'node[type="s3_bucket"]', style: { "shape": "ellipse" } },
        { selector: "edge", style: { "curve-style": "bezier", "target-arrow-shape": "triangle", "label": "", "line-color": "data(color)", "target-arrow-color": "data(color)", "width": "mapData(weight, 1, 3, 1.5, 4)" } },
        { selector: 'edge[edge_type="assume-role"]', style: { "line-style": "dashed" } },
      ],
    });

    cy.on("tap", "node", (evt) => {
      const n = evt.target;
      document.getElementById("selected").textContent = JSON.stringify(n.data(), null, 2);
    });

    cy.on("tap", "edge", (evt) => {
      const e = evt.target;
      document.getElementById("selected").textContent = JSON.stringify(e.data(), null, 2);
    });

    ["showCritical","showHighRisk","showAllowed","showAmbiguous","showDenied"].forEach(id => {
      document.getElementById(id).addEventListener("change", () => applyFilters(cy));
    });

    applyFilters(cy);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    document.getElementById("selected").textContent = `Error: ${msg}`;
  }
})();
