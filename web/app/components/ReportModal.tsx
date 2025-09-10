import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { X, Download, FileText, Calendar, Search, RefreshCw, Brain, Sparkles, CheckCircle } from 'lucide-react';
import apiClient, { type Report, type Engagement } from '../services/apiClient';

interface ReportModalProps {
  onClose: () => void;
}

const ReportModal = ({ onClose }: ReportModalProps) => {
  const [reports, setReports] = useState<Report[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEngagement, setSelectedEngagement] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [generating, setGenerating] = useState<string | null>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  }, [onClose]);

  const handleBackdropClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  }, [onClose]);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [reportsData, engagementsData] = await Promise.all([
        apiClient.getReports(),
        apiClient.getEngagements(),
      ]);
      
      setReports(reportsData);
      setEngagements(engagementsData);
    } catch (err: any) {
      console.error('Failed to load reports:', err);
      setError(apiClient.getUserFriendlyErrorMessage(err) || 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Focus on search input when modal opens
    if (searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [loadData]);

  const handleDownloadReport = useCallback(async (report: Report) => {
    try {
      const blob = await apiClient.downloadReport(report.id, report.type);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.name}.${report.type}`;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Failed to download report:', err);
      setError(apiClient.getUserFriendlyErrorMessage(err) || 'Failed to download report');
    }
  }, []);

  const handleGenerateReport = useCallback(async (engagementId: string, reportType: string = 'html', useAi: boolean = true) => {
    try {
      setGenerating(engagementId);
      await apiClient.generateReport(engagementId, reportType, useAi);
      await loadData(); // Refresh the reports list
    } catch (err: any) {
      console.error('Failed to generate report:', err);
      setError(apiClient.getUserFriendlyErrorMessage(err) || 'Failed to generate report');
    } finally {
      setGenerating(null);
    }
  }, [loadData]);

  const formatDate = useCallback((dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (error) {
      console.error('Invalid date:', dateString);
      return 'Invalid Date';
    }
  }, []);

  const getEngagementName = useCallback((engagementId: string) => {
    const engagement = engagements.find(e => e.id === engagementId);
    return engagement ? engagement.name : 'Unknown';
  }, [engagements]);

  const filteredReports = useMemo(() => {
    return reports.filter(report => {
      const matchesSearch = report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           getEngagementName(report.engagement_id).toLowerCase().includes(searchTerm.toLowerCase());
      const matchesEngagement = !selectedEngagement || report.engagement_id === selectedEngagement;
      const matchesType = !selectedType || report.type === selectedType;
      
      return matchesSearch && matchesEngagement && matchesType;
    });
  }, [reports, searchTerm, selectedEngagement, selectedType, getEngagementName]);

  const reportTypes = [...new Set(reports.map(r => r.type))];

  return (
    <div 
      className="modal-overlay"
      onClick={handleBackdropClick}
      onKeyDown={handleKeyDown}
      role="dialog"
      aria-modal="true"
      aria-labelledby="reports-modal-title"
    >
      <div className="modal-container" ref={modalRef}>
        <div className="modal-content">
          <div className="relative transform overflow-hidden rounded-lg bg-white text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-4xl">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h3 id="reports-modal-title" className="text-lg font-medium text-gray-900">Reports Management</h3>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600 transition-colors"
                aria-label="Close reports modal"
                type="button"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            {/* Filters */}
            <div className="p-6 border-b border-gray-200 bg-gray-50">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    ref={searchInputRef}
                    type="text"
                    placeholder="Search reports..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="form-input pl-10"
                    aria-label="Search reports"
                  />
                </div>

                {/* Engagement Filter */}
                <div>
                  <select
                    value={selectedEngagement}
                    onChange={(e) => setSelectedEngagement(e.target.value)}
                    className="select"
                    aria-label="Filter by engagement"
                  >
                    <option value="">All Engagements</option>
                    {engagements.map((engagement) => (
                      <option key={engagement.id} value={engagement.id}>
                        {engagement.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Report Type Filter */}
                <div>
                  <select
                    value={selectedType}
                    onChange={(e) => setSelectedType(e.target.value)}
                    className="select"
                    aria-label="Filter by report type"
                  >
                    <option value="">All Types</option>
                    {reportTypes.map((type) => (
                      <option key={type} value={type}>
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Refresh Button */}
                <div>
                  <button
                    onClick={loadData}
                    className="btn-outline flex items-center"
                    disabled={loading}
                    aria-label="Refresh reports list"
                    type="button"
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                    Refresh
                  </button>
                </div>
              </div>
            </div>

            {/* Content */}
            <div className="p-6">
              {loading ? (
                <div className="text-center py-8">
                  <div className="spinner mx-auto mb-4"></div>
                  <p className="text-gray-600">Loading reports...</p>
                </div>
              ) : error ? (
                <div className="text-center py-8" role="alert">
                  <FileText className="h-12 w-12 text-red-500 mx-auto mb-4" aria-hidden="true" />
                  <p className="text-red-600 mb-4">{error}</p>
                  <button onClick={loadData} className="btn-primary">
                    Retry
                  </button>
                </div>
              ) : (
                <>
                  {/* Generate Reports Section */}
                  <div className="mb-6">
                    <h4 className="text-md font-medium text-gray-900 mb-3">Generate New Report</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {engagements.filter(e => e.status === 'completed').map(engagement => {
                        const hasAiAnalysis = (engagement.findings_count ?? 0) > 0; // Assume AI analysis if findings exist
                        return (
                          <div key={engagement.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-blue-300 transition-colors">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center space-x-2 mb-1">
                                <p className="text-sm font-medium text-gray-900 truncate">{engagement.name}</p>
                                {hasAiAnalysis && (
                                  <div className="flex items-center space-x-1">
                                    <Brain className="h-3 w-3 text-blue-500" />
                                    <span className="text-xs text-blue-600 font-medium">AI Enhanced</span>
                                  </div>
                                )}
                              </div>
                              <p className="text-xs text-gray-500 mb-1">{engagement.target}</p>
                              <div className="flex items-center space-x-3 text-xs text-gray-400">
                                <span className="flex items-center space-x-1">
                                  <CheckCircle className="h-3 w-3" />
                                  <span>{engagement.findings_count ?? 0} findings</span>
                                </span>
                                {hasAiAnalysis && (
                                  <span className="flex items-center space-x-1 text-blue-500">
                                    <Sparkles className="h-3 w-3" />
                                    <span>AI Analysis Ready</span>
                                  </span>
                                )}
                              </div>
                            </div>
                            <button
                              onClick={() => handleGenerateReport(engagement.id)}
                              disabled={generating === engagement.id}
                              className="btn-primary ml-3 flex items-center space-x-2"
                              aria-label={`Generate ${hasAiAnalysis ? 'AI-enhanced' : ''} report for ${engagement.name}`}
                              type="button"
                            >
                              {generating === engagement.id ? (
                                <div className="spinner" aria-hidden="true"></div>
                              ) : (
                                <>
                                  <FileText className="h-4 w-4" aria-hidden="true" />
                                  {hasAiAnalysis && <Brain className="h-4 w-4 text-blue-200" aria-hidden="true" />}
                                </>
                              )}
                              <span>{generating === engagement.id ? 'Generating...' : (hasAiAnalysis ? 'Generate AI Report' : 'Generate Report')}</span>
                            </button>
                          </div>
                        );
                      })}
                    </div>
                    {engagements.filter(e => e.status === 'completed').length === 0 && (
                      <p className="text-gray-500 text-sm">No completed engagements available for report generation.</p>
                    )}
                  </div>

                  {/* Reports List */}
                  <div>
                    <h4 className="text-md font-medium text-gray-900 mb-3">
                      Existing Reports ({filteredReports.length})
                    </h4>
                    
                    {filteredReports.length > 0 ? (
                      <div className="overflow-x-auto">
                        <table className="table">
                          <thead className="table-header">
                            <tr>
                              <th className="table-header-cell">Report Name</th>
                              <th className="table-header-cell">Engagement</th>
                              <th className="table-header-cell">Type</th>
                              <th className="table-header-cell">Created</th>
                              <th className="table-header-cell">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="table-body">
                            {filteredReports.map((report) => {
                              const engagement = engagements.find(e => e.id === report.engagement_id);
                              const hasAiAnalysis = engagement && (engagement.findings_count ?? 0) > 0;
                              return (
                                <tr key={report.id}>
                                  <td className="table-cell">
                                    <div className="flex items-center space-x-2">
                                      <span className="font-medium">{report.name}</span>
                                      {hasAiAnalysis && (
                                        <div className="flex items-center space-x-1">
                                          <Brain className="h-3 w-3 text-blue-500" />
                                          <span className="text-xs text-blue-600 font-medium">AI</span>
                                        </div>
                                      )}
                                    </div>
                                  </td>
                                  <td className="table-cell">{getEngagementName(report.engagement_id)}</td>
                                  <td className="table-cell">
                                    <div className="flex items-center space-x-2">
                                      <span className="badge-info">
                                        {report.type.charAt(0).toUpperCase() + report.type.slice(1)}
                                      </span>
                                      {hasAiAnalysis && (
                                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                          <Sparkles className="h-3 w-3 mr-1" />
                                          Enhanced
                                        </span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="table-cell">
                                    <div className="flex items-center text-sm text-gray-500">
                                      <Calendar className="h-4 w-4 mr-1" />
                                      {formatDate(report.created_at)}
                                    </div>
                                  </td>
                                  <td className="table-cell">
                                    <button
                                      onClick={() => handleDownloadReport(report)}
                                      className="text-blue-600 hover:text-blue-800 transition-colors flex items-center space-x-1"
                                      aria-label={`Download ${hasAiAnalysis ? 'AI-enhanced' : ''} ${report.name} report`}
                                      title={`Download ${hasAiAnalysis ? 'AI-Enhanced ' : ''}Report`}
                                      type="button"
                                    >
                                      <Download className="h-4 w-4" />
                                      {hasAiAnalysis && <Brain className="h-3 w-3 text-blue-400" />}
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500">
                          {searchTerm || selectedEngagement || selectedType
                            ? 'No reports match your filters'
                            : 'No reports available'}
                        </p>
                        {(searchTerm || selectedEngagement || selectedType) && (
                          <button
                            onClick={() => {
                              setSearchTerm('');
                              setSelectedEngagement('');
                              setSelectedType('');
                            }}
                            className="btn-outline mt-4"
                          >
                            Clear Filters
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end p-6 border-t border-gray-200">
              <button onClick={onClose} className="btn-outline">
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportModal;