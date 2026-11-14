/** Read-only presentation of a generated, source-derived inventory. Not a verifier. */
export function validateCatalog(catalog) {
  if (!catalog || catalog.format !== 'stitch/site-facets/1' || typeof catalog.assurance !== 'string' || !Array.isArray(catalog.facets) || catalog.facets.length > 100) throw new TypeError('Unrecognized facet inventory.');
  const names = new Set();
  for (const facet of catalog.facets) {
    if (!facet || typeof facet.name !== 'string' || names.has(facet.name) || typeof facet.summary !== 'string' || typeof facet.evidenceStatus !== 'string' || !Number.isSafeInteger(facet.count) || facet.count < 0 || !/^app\/src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.lex\.tex$/.test(facet.source)) throw new TypeError('Invalid source facet record.');
    names.add(facet.name);
  }
  return catalog;
}

export function renderCatalog(document, catalog) {
  validateCatalog(catalog);
  const grid = document.createElement('div'); grid.className = 'facet-grid';
  for (const facet of catalog.facets) {
    const card = document.createElement('article'); card.className = 'facet-card';
    const heading = document.createElement('h3'); heading.textContent = facet.name;
    const summary = document.createElement('p'); summary.textContent = facet.summary;
    const count = document.createElement('span'); count.className = 'facet-count'; count.textContent = `${facet.count} declarations`;
    const evidence = document.createElement('p'); evidence.className = 'facet-status'; evidence.textContent = facet.evidenceStatus;
    const link = document.createElement('a'); link.textContent = 'Read source ↗'; link.href = `./${facet.source}`;
    card.append(heading, summary, count, evidence, link); grid.append(card);
  }
  document.getElementById('facetCatalogContent').replaceChildren(grid);
  document.getElementById('facetCatalogStatus').textContent = catalog.assurance;
}

if (typeof document !== 'undefined') {
  fetch(new URL('./facets.json', import.meta.url), { credentials: 'omit' }).then(response => {
    if (!response.ok) throw new Error('Facet inventory unavailable.');
    return response.json();
  }).then(catalog => renderCatalog(document, catalog)).catch(() => {
    document.getElementById('facetCatalogContent').textContent = 'The facet inventory could not be loaded. Inspect the source repository for the current model.';
    document.getElementById('facetCatalogStatus').textContent = 'No coverage or verification status inferred.';
  });
}
