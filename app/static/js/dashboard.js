// Dashboard JavaScript functionality for Avighna2 SIEM

$(document).ready(function() {
    // Load initial activity
    loadActivity();
    
    // Fix any existing scroll issues on page load
    fixScrolling();
    
    // Setup NLP query enter key handler
    $('#nlpQuery').on('keypress', function(e) {
        if (e.which === 13) {
            processNLPQuery();
        }
    });
});

// Show modals
function showIngestModal() {
    $('#ingestModal').modal('show');
}

function showScanModal() {
    $('#scanModal').modal('show');
}

function showGeoIPModal() {
    $('#geoipModal').modal('show');
}

// Show loading modal
function showLoading(text = 'Processing...', subtext = 'Please wait') {
    $('#loadingText').text(text);
    $('#loadingSubtext').text(subtext);
    $('#loadingModal').modal('show');
}

function hideLoading() {
    console.log('Hiding loading modal - FORCE MODE');
    
    // Immediately hide the modal
    $('#loadingModal').modal('hide');
    
    // Force hide everything immediately without delay
    $('#loadingModal').hide();
    $('.modal-backdrop').remove();
    $('body').removeClass('modal-open');
    $('body').css({
        'padding-right': '',
        'overflow': '',
        'overflow-x': '',
        'overflow-y': ''
    });
    $('html').css('overflow', '');
    
    // Also try to hide any other stuck modals
    $('.modal').modal('hide');
    $('.modal').hide();
    
    console.log('Loading modal hidden forcefully');
}

// Emergency function to force hide modal
function forceHideModal() {
    console.log('EMERGENCY: Force hiding all modals');
    $('.modal').modal('hide');
    $('.modal').hide();
    $('.modal-backdrop').remove();
    $('body').removeClass('modal-open');
    $('body').css('padding-right', '');
    $('body').css('overflow', ''); // Reset overflow
    $('#loadingModal').hide();
    console.log('All modals force-hidden via emergency function');
}

// Fix scroll issues
function fixScrolling() {
    console.log('Fixing scrolling issues');
    $('.modal-backdrop').remove();
    $('body').removeClass('modal-open');
    $('body').css({
        'padding-right': '',
        'overflow': '',
        'overflow-x': '',
        'overflow-y': ''
    });
    $('html').css({
        'overflow': '',
        'overflow-x': '',
        'overflow-y': ''
    });
    console.log('Scrolling fixed');
}

// Log Ingestion
function ingestLog() {
    const fileInput = document.getElementById('logFile');
    const filePath = $('#filePath').val().trim();
    
    console.log('Ingest function called');
    console.log('File input files:', fileInput.files.length);
    console.log('File path:', filePath);
    
    if (!fileInput.files[0] && !filePath) {
        showAlert('Please select a file or enter a file path', 'warning');
        return;
    }
    
    showLoading('Processing log file...', 'Parsing events and analyzing patterns');
    
    if (fileInput.files[0]) {
        // File upload
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        console.log('Uploading file:', fileInput.files[0].name);
        
        $.ajax({
            url: '/api/ingest',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                console.log('SUCCESS CALLBACK - File upload response:', response);
                
                // EMERGENCY: Hide loading modal immediately
                console.log('EMERGENCY HIDE: Forcing modal to close');
                $('#loadingModal').modal('hide');
                $('#loadingModal').hide();
                $('.modal-backdrop').remove();
                $('body').removeClass('modal-open');
                
                hideLoading();
                $('#ingestModal').modal('hide');
                
                // Force show results even if success flag is missing
                if (response && (response.success || response.events_count !== undefined)) {
                    showIngestResults(response);
                } else if (response.error) {
                    showAlert(response.error, 'danger');
                } else {
                    showAlert('Processing completed but no results received', 'warning');
                }
                
                loadActivity();
            },
            error: function(xhr) {
                console.error('File upload error:', xhr);
                hideLoading();
                
                // Try to parse error response
                let errorMsg = 'Failed to process log file';
                try {
                    const errorResponse = JSON.parse(xhr.responseText);
                    errorMsg = errorResponse.error || errorMsg;
                } catch (e) {
                    errorMsg = xhr.statusText || errorMsg;
                }
                
                showAlert(errorMsg, 'danger');
            }
        });
    } else {
        // Send as JSON for file path
        console.log('Processing file path:', filePath);
        $.ajax({
            url: '/api/ingest',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ filepath: filePath }),
            success: function(response) {
                console.log('SUCCESS CALLBACK - File path response:', response);
                
                // EMERGENCY: Hide loading modal immediately
                console.log('EMERGENCY HIDE: Forcing modal to close');
                $('#loadingModal').modal('hide');
                $('#loadingModal').hide();
                $('.modal-backdrop').remove();
                $('body').removeClass('modal-open');
                
                hideLoading();
                $('#ingestModal').modal('hide');
                
                // Force show results even if success flag is missing
                if (response && (response.success || response.events_count !== undefined)) {
                    showIngestResults(response);
                } else if (response.error) {
                    showAlert(response.error, 'danger');
                } else {
                    showAlert('Processing completed but no results received', 'warning');
                }
                
                loadActivity(); // Refresh activity log
            },
            error: function(xhr) {
                console.error('File path error:', xhr);
                hideLoading();
                
                // Try to parse error response
                let errorMsg = 'Failed to process log file';
                try {
                    const errorResponse = JSON.parse(xhr.responseText);
                    errorMsg = errorResponse.error || errorMsg;
                } catch (e) {
                    errorMsg = xhr.statusText || errorMsg;
                }
                
                showAlert(errorMsg, 'danger');
            }
        });
    }
}

function showIngestResults(data) {
    console.log('Displaying ingest results:', data);
    
    if (data.error) {
        let html = `
            <div class="alert alert-danger">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Ingestion Error</h6>
                <p>${data.error}</p>
            </div>
        `;
        $('#resultsPanel').html(html);
        showAlert(data.error, 'danger');
        return;
    }

    let html = `
        <div class="alert alert-${data.brute_force_detected ? 'danger' : 'success'}">
            <h6><i class="fas fa-chart-bar me-2"></i>Ingestion Results</h6>
            <div class="row">
                <div class="col-md-6">
                    <strong>Events Processed:</strong> ${data.events_count || 0}<br>
                    <strong>Failed Attempts:</strong> ${data.failed_attempts || 0}
                </div>
                <div class="col-md-6">
                    ${data.brute_force_detected ? 
                        '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle me-1"></i>Brute Force Detected!</span>' : 
                        '<span class="badge bg-success"><i class="fas fa-check me-1"></i>No Threats Detected</span>'
                    }
                </div>
            </div>
        </div>
        <div class="mt-3">
            <h6>Summary:</h6>
            <pre class="bg-light p-3 rounded" style="color: #212529 !important;">${data.summary || 'No summary available'}</pre>
        </div>
    `;
    
    // Force update the results panel
    const resultsPanel = $('#resultsPanel');
    resultsPanel.html(html);
    resultsPanel.show();
    
    // Scroll to results
    $('html, body').animate({
        scrollTop: resultsPanel.offset().top
    }, 500);
    
    if (data.brute_force_detected) {
        showAlert('⚠️ Brute force attack pattern detected in logs!', 'danger');
    } else {
        showAlert('✅ Log file processed successfully!', 'success');
    }
}

// File Scanner
function scanFile() {
    const fileInput = document.getElementById('scanFile');
    
    if (!fileInput.files[0]) {
        showAlert('Please select a file to scan', 'warning');
        return;
    }
    
    showLoading('Scanning file...', 'Checking against YARA rules');
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    $.ajax({
        url: '/api/scan',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            hideLoading();
            $('#scanModal').modal('hide');
            showScanResults(response);
            loadActivity();
        },
        error: function(xhr) {
            hideLoading();
            const error = xhr.responseJSON?.error || 'Failed to scan file';
            showAlert(error, 'danger');
        }
    });
}

function showScanResults(data) {
    const result = data.result;
    const suspicious = data.suspicious;
    
    let html = `
        <div class="alert alert-${suspicious ? 'danger' : 'success'}">
            <h6><i class="fas fa-search me-2"></i>Scan Results</h6>
            <div class="row">
                <div class="col-md-6">
                    <strong>Status:</strong> ${result.status}<br>
                    <strong>Matches Found:</strong> ${result.matches ? result.matches.length : 0}
                </div>
                <div class="col-md-6">
                    ${suspicious ? 
                        '<span class="badge bg-danger"><i class="fas fa-exclamation-triangle me-1"></i>Suspicious Patterns Found!</span>' : 
                        '<span class="badge bg-success"><i class="fas fa-check me-1"></i>Clean</span>'
                    }
                </div>
            </div>
        </div>
    `;
    
    if (result.matches && result.matches.length > 0) {
        html += `
            <div class="mt-3">
                <h6>Detected Patterns:</h6>
                <ul class="list-group">
        `;
        result.matches.forEach(match => {
            html += `<li class="list-group-item list-group-item-danger">
                <i class="fas fa-bug me-2"></i>${match}
            </li>`;
        });
        html += '</ul></div>';
    }
    
    $('#resultsPanel').html(html);
    
    if (suspicious) {
        showAlert('⚠️ Suspicious patterns detected in file!', 'danger');
    }
}

// Enhanced GeoIP Lookup - supports both IP addresses and domain names
function lookupGeoIP() {
    const target = $('#ipAddress').val().trim();
    
    if (!target) {
        showAlert('Please enter an IP address or domain name', 'warning');
        return;
    }
    
    // Determine if input is IP or domain
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target);
    const lookupType = isIP ? 'IP address' : 'domain name';

    showLoading(`Looking up ${lookupType}...`, 'Fetching geolocation and website data');
    
    $.ajax({
        url: '/api/geoip',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip: target }), // API accepts both IP and domain
        success: function(response) {
            console.log('GeoIP response:', response);
            hideLoading();
            $('#geoipModal').modal('hide');
            
            if (response && response.success) {
                showGeoIPResults(response);
                showAlert(`✅ ${lookupType} lookup completed!`, 'success');
                loadActivity();
            } else if (response && response.error) {
                showAlert(`❌ ${response.error}`, 'danger');
            } else {
                showAlert('No geolocation data found', 'warning');
            }
        },
        error: function(xhr) {
            console.error('GeoIP error:', xhr);
            hideLoading();
            
            let errorMsg = `Failed to lookup ${lookupType}`;
            try {
                const errorResponse = JSON.parse(xhr.responseText);
                errorMsg = errorResponse.error || errorMsg;
            } catch (e) {
                errorMsg = xhr.statusText || errorMsg;
            }
            
            showAlert(errorMsg, 'danger');
        }
    });
}

function showGeoIPResults(data) {
    console.log('Displaying GeoIP results:', data);
    const info = data.info;
    const target = data.target || 'Unknown';

    if (!info) {
        showAlert('No information available', 'warning');
        return;
    }

    // Check for error
    if (info.error) {
        showAlert(`❌ ${info.error}`, 'danger');
        return;
    }
    
    let html = `
        <div class="alert alert-primary">
            <h5><i class="fas fa-globe me-2"></i>Geographic Information</h5>
            <div class="mt-2">
                <span class="badge bg-secondary me-2">Target: ${info.original_input || target}</span>
                <span class="badge bg-info me-2">Type: ${info.input_type === 'domain' ? 'Domain Name' : 'IP Address'}</span>
                ${info.source ? `<span class="badge bg-success">Source: ${info.source}</span>` : ''}
            </div>
        </div>
    `;

    // Website Information (if domain)
    if (info.website_info) {
        html += `
            <div class="card mb-3">
                <div class="card-header bg-info text-white">
                    <h6 class="mb-0"><i class="fas fa-globe me-2"></i>Website Information</h6>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <strong>Domain:</strong> ${info.website_info.domain || 'N/A'}
                        </div>
                        <div class="col-md-6">
                            <strong>Website Name:</strong> ${info.website_info.website_name || 'N/A'}
                        </div>
                        <div class="col-md-6">
                            <strong>Resolved IP:</strong> ${info.website_info.resolved_ip || 'N/A'}
                        </div>
                        <div class="col-md-6">
                            <strong>Server:</strong> ${info.website_info.server || 'Unknown'}
                        </div>
                        ${info.website_info.final_url ? `
                        <div class="col-12 mt-2">
                            <strong>Final URL:</strong> 
                            <a href="${info.website_info.final_url}" target="_blank" class="text-decoration-none">
                                ${info.website_info.final_url} <i class="fas fa-external-link-alt ms-1"></i>
                            </a>
                        </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }
    
    // Geographic Information
    html += `
        <div class="card mb-3">
            <div class="card-header bg-success text-white">
                <h6 class="mb-0"><i class="fas fa-map-marker-alt me-2"></i>Geographic Location</h6>
            </div>
            <div class="card-body">
                <div class="row">
    `;

    // Display key geographic fields
    const geoFields = {
        'country': 'Country',
        'city': 'City',
        'latitude': 'Latitude',
        'longitude': 'Longitude',
        'isp': 'ISP/Organization'
    };

    for (const [key, label] of Object.entries(geoFields)) {
        if (info[key] !== undefined && info[key] !== null) {
            html += `
                <div class="col-md-6 mb-2">
                    <strong>${label}:</strong> ${info[key]}
                </div>
            `;
        }
    }

    html += `
                </div>
            </div>
        </div>
    `;

    // Additional Information (any other fields)
    const displayedFields = new Set(['original_input', 'resolved_ip', 'input_type', 'website_info', 'source', 'country', 'city', 'latitude', 'longitude', 'isp']);
    const additionalFields = Object.entries(info).filter(([key, value]) =>
        !displayedFields.has(key) && value !== null && value !== undefined && value !== ''
    );

    if (additionalFields.length > 0) {
        html += `
            <div class="card">
                <div class="card-header bg-secondary text-white">
                    <h6 class="mb-0"><i class="fas fa-info-circle me-2"></i>Additional Information</h6>
                </div>
                <div class="card-body">
                    <div class="row">
        `;

        additionalFields.forEach(([key, value]) => {
            html += `
                <div class="col-md-6 mb-2">
                    <strong>${key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ')}:</strong> ${value}
                </div>
            `;
        });

        html += `
                    </div>
                </div>
            </div>
        `;
    }

    // Force update the results panel
    const resultsPanel = $('#resultsPanel');
    resultsPanel.html(html);
    resultsPanel.show();
    
    // Scroll to results
    $('html, body').animate({
        scrollTop: resultsPanel.offset().top
    }, 500);
}

// NLP Query Processing
function processNLPQuery() {
    const query = $('#nlpQuery').val().trim();
    
    if (!query) {
        showAlert('Please enter a query', 'warning');
        return;
    }
    
    showLoading('Processing query...', 'Analyzing request');
    
    $.ajax({
        url: '/api/nlp',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ query: query }),
        success: function(response) {
            console.log('NLP response:', response);
            hideLoading();
            
            if (response && response.success && response.response) {
                showNLPResponse(response.response);
                showAlert('✅ Query processed successfully!', 'success');
                loadActivity();
            } else if (response && response.response) {
                // Handle case where success flag might be missing
                showNLPResponse(response.response);
                showAlert('✅ Query processed!', 'info');
                loadActivity();
            } else {
                const errorMsg = response?.error || 'Could not process query - no matching patterns found';
                showAlert(errorMsg, 'warning');
            }
        },
        error: function(xhr) {
            console.error('NLP error:', xhr);
            hideLoading();
            
            let errorMsg = 'Failed to process query';
            try {
                const errorResponse = JSON.parse(xhr.responseText);
                errorMsg = errorResponse.error || errorMsg;
            } catch (e) {
                errorMsg = xhr.statusText || errorMsg;
            }
            
            showAlert(errorMsg, 'danger');
        }
    });
}

function showNLPResponse(response) {
    console.log('Showing NLP response:', response);
    
    // Enhanced NLP response with better formatting
    const formattedResponse = `
        <div class="nlp-response">
            <h6><i class="fas fa-robot me-2"></i>Avighna2 Analysis</h6>
            <div style="color: #212529 !important;">${response}</div>
        </div>
    `;

    // Show in results panel instead of separate section
    const resultsPanel = $('#resultsPanel');
    resultsPanel.html(formattedResponse);
    resultsPanel.show();
    
    // Scroll to response
    $('html, body').animate({
        scrollTop: resultsPanel.offset().top - 100
    }, 500);
    
    // Clear the query input
    $('#nlpQuery').val('');

    // Add success visual feedback
    $('#nlpQuery').closest('.card').addClass('pulse');
    setTimeout(() => {
        $('#nlpQuery').closest('.card').removeClass('pulse');
    }, 2000);
}

// Report Generation
function generateReport() {
    if (!confirm('Generate a forensic report? This may take a few moments.')) {
        return;
    }
    
    showLoading('Generating report...', 'Creating forensic analysis');
    
    $.ajax({
        url: '/api/report',
        type: 'POST',
        success: function(response) {
            console.log('Report response:', response);
            hideLoading();
            
            if (response && (response.success || response.report_path)) {
                showReportResults(response);
                showAlert('✅ Forensic report generated successfully!', 'success');
                loadActivity();
            } else {
                const errorMsg = response?.error || 'Failed to generate report';
                showAlert(errorMsg, 'danger');
            }
        },
        error: function(xhr) {
            console.error('Report error:', xhr);
            hideLoading();
            
            let errorMsg = 'Failed to generate report';
            try {
                const errorResponse = JSON.parse(xhr.responseText);
                errorMsg = errorResponse.error || errorMsg;
            } catch (e) {
                errorMsg = xhr.statusText || errorMsg;
            }
            
            showAlert(errorMsg, 'danger');
        }
    });
}

function showReportResults(data) {
    console.log('Displaying report results:', data);
    
    const downloadUrl = data.download_url || '#';
    const fileName = data.report_path || 'report.pdf';

    let html = `
        <div class="alert alert-success border-success">
            <div class="d-flex align-items-center justify-content-between mb-3">
                <h5 class="mb-0">
                    <i class="fas fa-file-pdf me-2 text-danger"></i>
                    📄 Forensic Report Generated
                </h5>
                <span class="badge bg-success fs-6">READY</span>
            </div>

            <div class="row align-items-center">
                <div class="col-md-8">
                    <div class="report-details">
                        <p class="mb-2">
                            <strong>📁 File:</strong>
                            <span class="text-primary">${fileName}</span>
                        </p>
                        <p class="mb-2">
                            <strong>🔐 SHA256:</strong> 
                            <code class="text-muted small">${data.hash || 'Not available'}</code>
                        </p>
                        <p class="mb-0 text-success">
                            <i class="fas fa-check-circle me-1"></i>
                            Report saved to reports/ directory
                        </p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="d-grid gap-2">
                        <a href="${downloadUrl}" 
                           class="btn btn-primary btn-lg download-btn" 
                           download="${fileName}"
                           onclick="triggerDownload('${downloadUrl}', '${fileName}')">
                            <i class="fas fa-download me-2"></i>
                            📥 Download PDF
                        </a>
                        <small class="text-muted text-center">
                            Click to download report
                        </small>
                    </div>
                </div>
            </div>
        </div>

        <div class="mt-3 p-3 bg-light rounded">
            <h6><i class="fas fa-info-circle me-2 text-info"></i>Report Information</h6>
            <ul class="list-unstyled mb-0">
                <li>✅ Password-protected forensic report</li>
                <li>📊 Contains comprehensive security analysis</li>
                <li>🛡️ Includes threat indicators and recommendations</li>
                <li>📍 Saved in: <code>reports/${fileName}</code></li>
            </ul>
        </div>
    `;
    
    // Force update the results panel
    const resultsPanel = $('#resultsPanel');
    resultsPanel.html(html);
    resultsPanel.show();
    
    // Auto-trigger download after 2 seconds
    setTimeout(() => {
        if (downloadUrl !== '#') {
            showAlert('🚀 Download starting automatically...', 'info');
            triggerDownload(downloadUrl, fileName);
        }
    }, 2000);

    // Scroll to results
    $('html, body').animate({
        scrollTop: resultsPanel.offset().top
    }, 500);
}

// Function to trigger download
function triggerDownload(url, filename) {
    console.log('Triggering download:', url, filename);

    // Create temporary download link
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);

    // Trigger download
    link.click();

    // Clean up
    document.body.removeChild(link);

    showAlert(`📥 Downloading ${filename}...`, 'success');
}

// Activity Log
function loadActivity() {
    $.ajax({
        url: '/api/activity',
        type: 'GET',
        success: function(response) {
            if (response.success) {
                showActivity(response.activities);
            } else {
                $('#activityLog').html('<div class="text-center text-muted py-4">Failed to load activity</div>');
            }
        },
        error: function() {
            $('#activityLog').html('<div class="text-center text-muted py-4">Failed to load activity</div>');
        }
    });
}

function showActivity(activities) {
    let html = '';
    
    if (activities.length === 0) {
        html = '<div class="text-center text-muted py-4">No recent activity</div>';
    } else {
        activities.forEach(activity => {
            const icon = getActivityIcon(activity.action);
            const time = new Date(activity.timestamp).toLocaleString();
            
            html += `
                <div class="activity-item">
                    <div class="d-flex align-items-start">
                        <i class="fas fa-${icon} me-3 mt-1"></i>
                        <div class="flex-grow-1">
                            <div class="fw-semibold">${activity.action}</div>
                            <div class="text-muted small">${activity.summary}</div>
                            <div class="text-muted small">${time}</div>
                        </div>
                    </div>
                </div>
            `;
        });
    }
    
    $('#activityLog').html(html);
}

function getActivityIcon(action) {
    const icons = {
        'ingest': 'upload',
        'scan_file': 'search',
        'geoip': 'globe',
        'nlp_query': 'comments',
        'report': 'file-pdf',
        'quarantine': 'shield-alt'
    };
    return icons[action] || 'cog';
}

// Utility function to show alerts
function showAlert(message, type = 'info') {
    console.log('Showing alert:', message, type);
    
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert" style="position: relative; z-index: 1050;">
            <i class="fas fa-${type === 'danger' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Remove any existing alerts of the same type
    $(`.alert-${type}`).alert('close');
    
    // Create temporary container for the alert
    const alertContainer = $('<div>').html(alertHtml);
    $('main').prepend(alertContainer);
    
    // Scroll to top to make alert visible
    $('html, body').animate({
        scrollTop: 0
    }, 300);
    
    // Auto-remove after 8 seconds (increased time)
    setTimeout(() => {
        alertContainer.find('.alert').alert('close');
    }, 8000);
}