/**
 * AegisOSINT - Interactive Threat Graph Visualizer (Cytoscape.js)
 */

let cy = null;

function initCytoscapeGraph(elements) {
  const container = document.getElementById('cytoscape-container');
  if (!container) return;

  if (cy) {
    cy.destroy();
  }

  cy = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#F3F4F6',
          'font-size': '10px',
          'font-family': 'JetBrains Mono, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          'background-color': 'data(color)',
          'shape': 'data(shape)',
          'width': 'data(size)',
          'height': 'data(size)',
          'border-width': 2,
          'border-color': '#1E293B',
          'text-outline-color': '#0F172A',
          'text-outline-width': 2
        }
      },
      {
        selector: 'edge',
        style: {
          'label': 'data(relationship)',
          'font-size': '8px',
          'font-family': 'JetBrains Mono, sans-serif',
          'color': '#94A3B8',
          'text-rotation': 'autorotate',
          'text-margin-y': -8,
          'line-color': '#334155',
          'target-arrow-color': '#475569',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'width': 1.5,
          'arrow-scale': 0.8
        }
      },
      {
        selector: ':selected',
        style: {
          'border-width': 3,
          'border-color': '#818CF8',
          'line-color': '#818CF8',
          'target-arrow-color': '#818CF8'
        }
      }
    ],
    layout: {
      name: 'cose',
      idealEdgeLength: 100,
      nodeOverlap: 20,
      refresh: 20,
      fit: true,
      padding: 30,
      randomize: false,
      componentSpacing: 100,
      nodeRepulsion: 400000,
      edgeElasticity: 100,
      nestingFactor: 5,
      gravity: 80,
      numIter: 1000
    }
  });

  // Node click event
  cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    const data = node.data();
    alert(`[ENTITY DETAILS]\nLabel: ${data.label}\nType: ${data.entity_type}\nConnected Links: ${data.degree || cy.degree(node)}`);
  });
}

function applyGraphLayout(layoutName) {
  if (!cy) return;
  const layout = cy.layout({
    name: layoutName,
    animate: true,
    animationDuration: 500,
    fit: true,
    padding: 30
  });
  layout.run();
}
