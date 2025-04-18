// Initialize Lucide icons
lucide.createIcons();

// Menu functionality
document.querySelectorAll('.menu-button').forEach(button => {
  button.addEventListener('click', () => {
    const menuItem = button.parentElement;
    if (menuItem.querySelector('.submenu')) {
      menuItem.classList.toggle('active');
    }
  });
});


// URL data
const urlData = [
  {
    id: 1,
    url: 'malicious-site.com/payload',
    classification: 'High Risk',
    type: 'Phishing',
    detectedAt: '2024-03-15',
    status: 'Blocked',
  },
  {
    id: 2,
    url: 'suspicious-domain.net/script',
    classification: 'Medium Risk',
    type: 'Malware',
    detectedAt: '2024-03-14',
    status: 'Blocked',
  },
  {
    id: 3,
    url: 'fake-login.org/form',
    classification: 'High Risk',
    type: 'Phishing',
    detectedAt: '2024-03-13',
    status: 'Blocked',
  },
];

// Populate URL table
const urlTableBody = document.getElementById('urlTableBody');
urlData.forEach(url => {
  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${url.url}</td>
    <td>
      <span class="classification-tag ${url.classification === 'High Risk' ? 'high-risk' : 'medium-risk'}">
        ${url.classification}
      </span>
    </td>
    <td>${url.type}</td>
    <td>${url.detectedAt}</td>
    <td>
      <span class="status-indicator ${url.status.toLowerCase()}">
        <i data-lucide="${url.status === 'Blocked' ? 'x-circle' : 'check-circle'}"></i>
        ${url.status}
      </span>
    </td>
    <td>
      <button class="action-button" data-id="${url.id}">View Details</button>
    </td>
  `;
  urlTableBody.appendChild(row);
});

// Re-initialize icons for dynamically added content
lucide.createIcons();

// Modal functionality
const modal = document.getElementById('urlModal');
const modalDetails = document.getElementById('modalDetails');

document.querySelectorAll('.action-button').forEach(button => {
  button.addEventListener('click', () => {
    const urlId = parseInt(button.dataset.id);
    const url = urlData.find(u => u.id === urlId);
    
    modalDetails.innerHTML = `
      <div class="detail-item">
        <label>URL</label>
        <p>${url.url}</p>
      </div>
      <div class="detail-item">
        <label>Classification</label>
        <p>${url.classification}</p>
      </div>
      <div class="detail-item">
        <label>Type</label>
        <p>${url.type}</p>
      </div>
      <div class="detail-item">
        <label>Detection Date</label>
        <p>${url.detectedAt}</p>
      </div>
      <div class="detail-item">
        <label>Status</label>
        <p>${url.status}</p>
      </div>
    `;
    
    modal.classList.add('active');
  });
});

document.querySelector('.modal-close').addEventListener('click', () => {
  modal.classList.remove('active');
});

// Close modal when clicking outside
modal.addEventListener('click', (e) => {
  if (e.target === modal) {
    modal.classList.remove('active');
  }
});

// Handle window resize for charts
window.addEventListener('resize', () => {
  ReactDOM.render(threatChart, document.getElementById('threatChart'));
  ReactDOM.render(accessChart, document.getElementById('accessChart'));
});