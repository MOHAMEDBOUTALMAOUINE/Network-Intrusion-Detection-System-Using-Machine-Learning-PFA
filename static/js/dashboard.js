// Initialisation robuste de classStyles depuis le HTML
try {
    const classStylesScript = document.getElementById('classStylesData');
    if (classStylesScript) {
        window.classStyles = JSON.parse(classStylesScript.textContent);
    }
} catch (e) {
    window.classStyles = {};
}
const classStyles = window.classStyles || {};

// Variables pour stocker les instances des graphiques
let predictionChart = null;
let timelineChart = null;

function refreshData() {
    showLoading();
    fetch('/results')
        .then(response => response.json())
        .then(data => {
            updateDashboard(data);
            hideLoading();
        })
        .catch(error => {
            console.error('Erreur lors du rafraîchissement:', error);
            hideLoading();
            showError('Erreur lors du chargement des données');
        });
}

function updateDashboard(data) {
    // Mise à jour du tableau des résultats
    const resultsTable = document.getElementById('resultsTable');
    resultsTable.style.opacity = '0';
    setTimeout(() => {
        resultsTable.innerHTML = data.table;
        resultsTable.style.opacity = '1';
        // Active DataTables si le tableau existe
        if (resultsTable.querySelector('table')) {
            $(resultsTable.querySelector('table')).DataTable({
                language: {
                    url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/fr-FR.json'
                },
                pageLength: 5,
                lengthMenu: [5, 10, 25, 50],
                order: [],
                destroy: true
            });
        }
    }, 300);

    // Mise à jour des statistiques
    updateStats(data.stats);
    
    // Mise à jour des graphiques
    updateCharts(data.stats);
    
    // Mise à jour de l'activité récente
    updateRecentActivity(data.stats);
    
    // Mise à jour de la date de dernière mise à jour
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

    // Mise à jour du graphique temporel
    updateTimelineChart(data.time_series);
}

function updateStats(stats) {
    // Mise à jour des compteurs
    document.getElementById('totalSamples').textContent = stats.total_samples;
    document.getElementById('benignCount').textContent = stats.prediction_counts['BENIGN'] || 0;
    document.getElementById('attackCount').textContent = 
        Object.entries(stats.prediction_counts)
            .filter(([key]) => key !== 'BENIGN')
            .reduce((sum, [_, value]) => sum + value, 0);
    document.getElementById('avgConfidence').textContent = 
        `${(stats.average_confidence * 100).toFixed(1)}%`;
}

function updateCharts(stats) {
    const ctx = document.getElementById('predictionChart').getContext('2d');
    
    // Détruire le graphique existant s'il existe
    if (predictionChart) {
        predictionChart.destroy();
    }

    // Préparer les données
    const labels = Object.keys(stats.prediction_counts);
    const data = Object.values(stats.prediction_counts);
    const backgroundColors = labels.map(label => classStyles[label]?.color || '#888');

    // Créer le nouveau graphique
    predictionChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Répartition des types de trafic',
                    font: {
                        size: 16
                    }
                }
            }
        }
    });
}

function updateTimelineChart(time_series) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    // Détruire le graphique existant s'il existe
    if (timelineChart) {
        timelineChart.destroy();
    }

    // Préparer les données
    const labels = Object.keys(time_series).sort();
    const datasets = [];
    const attackTypes = new Set();
    
    // Collecter tous les types d'attaques
    for (const hour in time_series) {
        for (const type in time_series[hour]) {
            attackTypes.add(type);
        }
    }

    // Créer un dataset pour chaque type d'attaque
    attackTypes.forEach(type => {
        const data = labels.map(hour => time_series[hour][type] || 0);
        datasets.push({
            label: type,
            data: data,
            borderColor: classStyles[type]?.color || '#888',
            backgroundColor: classStyles[type]?.color + '20' || '#8888',
            fill: false,
            tension: 0.4
        });
    });

    // Créer le nouveau graphique
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Évolution des attaques',
                    font: {
                        size: 16
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Nombre d\'attaques'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Heure'
                    }
                }
            }
        }
    });
}

function updateRecentActivity(stats) {
    const activityList = document.getElementById('recentActivity');
    const activities = [];
    
    // Ajouter les activités basées sur les prédictions
    Object.entries(stats.prediction_counts).forEach(([type, count]) => {
        if (count > 0) {
            activities.push({
                type: type,
                count: count,
                icon: classStyles[type]?.icon || 'question-circle',
                color: classStyles[type]?.color || '#888'
            });
        }
    });
    
    // Trier par nombre d'occurrences
    activities.sort((a, b) => b.count - a.count);
    
    // Générer le HTML
    const html = activities.map(activity => `
        <div class="activity-item">
            <div class="activity-icon" style="background-color: ${activity.color}20; color: ${activity.color}">
                <i class="bi bi-${activity.icon}"></i>
            </div>
            <div class="activity-info">
                <div class="activity-title">${activity.type}</div>
                <div class="activity-count">${activity.count} détections</div>
            </div>
        </div>
    `).join('');
    
    activityList.innerHTML = html || '<div class="text-center text-muted">Aucune activité récente</div>';
}

// Fonctions utilitaires
function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'toast error';
    toast.innerHTML = `
        <i class="bi bi-exclamation-circle"></i>
        <span>${message}</span>
        <button class="toast-close">&times;</button>
    `;
    document.getElementById('toastContainer').appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

// Ajout des styles de transition
document.head.insertAdjacentHTML('beforeend', `
    <style>
        #resultsTable, #statsContainer, #noResultsMessage {
            transition: opacity 0.3s ease;
        }
        .loading-overlay {
            transition: opacity 0.3s ease;
        }
        .activity-item {
            transition: transform 0.2s ease;
        }
        .activity-item:hover {
            transform: translateX(5px);
        }
    </style>
`);

// Rafraîchissement automatique toutes les 10 secondes
setInterval(refreshData, 10000);

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', refreshData);

// Gestion du thème clair/sombre
const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
    themeToggle.onclick = function() {
        document.body.classList.toggle('dark-mode');
        const isDark = document.body.classList.contains('dark-mode');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        themeToggle.innerHTML = isDark ? '<i class="bi bi-sun"></i>' : '<i class="bi bi-moon"></i>';
    };
    // Initialisation au chargement
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
        themeToggle.innerHTML = '<i class="bi bi-sun"></i>';
    } else {
        themeToggle.innerHTML = '<i class="bi bi-moon"></i>';
    }
} 