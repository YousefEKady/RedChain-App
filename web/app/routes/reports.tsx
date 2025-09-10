import { useState, useEffect, useCallback } from 'react';
import { 
  FileText, 
  Download, 
  RefreshCw, 
  Search
} from 'lucide-react';
import apiClient, { type Report, type Engagement } from '../services/apiClient';
import ReportModal from '../components/ReportModal';
import SchedulerPanel from '../components/SchedulerPanel';

export function meta() {
  return [
    { title: "Reports Management - Red Team Automation" },
    { name: "description", content: "Manage reports and configure automatic report generation" },
  ];
}

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEngagement, setSelectedEngagement] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [showReportModal, setShowReportModal] = useState(false);

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
      console.error('Failed to load data:', err);
      setError(apiClient.getUserFriendlyErrorMessage(err) || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleDownloadReport = async (report: Report) => {
    try {
      const blob = await apiClient.downloadReport(report.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `${report.name}.${report.type}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      console.error('Failed to download report:', err);
      alert(apiClient.getUserFriendlyErrorMessage(err) || 'Failed to download report');
    }
  };

  const filteredReports = reports.filter(report => {
    const matchesSearch = report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.engagement_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesEngagement = !selectedEngagement || report.engagement_id === selectedEngagement;
    const matchesType = !selectedType || report.type === selectedType;
    
    return matchesSearch && matchesEngagement && matchesType;
  });

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Reports Management</h1>
          <p className="mt-2 text-gray-600">Manage your security reports and configure automatic generation</p>
        </div>

        {/* Automatic Report Generation Section */}
        <div className="mb-8">
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Automatic Report Generation</h2>
              <p className="text-sm text-gray-600 mt-1">Configure and manage automated report generation settings</p>
            </div>
            <div className="p-6">
              <SchedulerPanel />
            </div>
          </div>
        </div>

        {/* Reports List Section */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">All Reports</h2>
            <div className="flex gap-2">
              <button 
                onClick={loadData} 
                className="btn-outline"
                disabled={loading}
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button onClick={() => setShowReportModal(true)} className="btn-primary">
                <FileText className="h-4 w-4 mr-2" />
                Generate Report
              </button>
            </div>
          </div>

          {/* Filters */}
          <div className="p-6 border-b border-gray-200">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <input
                  type="text"
                  placeholder="Search reports..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="input pl-10"
                />
              </div>
              <select
                value={selectedEngagement}
                onChange={(e) => setSelectedEngagement(e.target.value)}
                className="input"
              >
                <option value="">All Engagements</option>
                {engagements.map(engagement => (
                  <option key={engagement.id} value={engagement.id}>
                    {engagement.name || engagement.id}
                  </option>
                ))}
              </select>
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="input"
              >
                <option value="">All Types</option>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="pdf">PDF</option>
              </select>
            </div>
          </div>

          {/* Reports Table */}
          <div className="p-6">
            {loading ? (
              <div className="text-center py-8">
                <RefreshCw className="h-8 w-8 text-blue-500 mx-auto mb-4 animate-spin" />
                <p className="text-gray-500">Loading reports...</p>
              </div>
            ) : error ? (
              <div className="text-center py-8">
                <FileText className="h-12 w-12 text-red-500 mx-auto mb-4" />
                <p className="text-red-600 mb-4">{error}</p>
                <button onClick={loadData} className="btn-primary">
                  Retry
                </button>
              </div>
            ) : filteredReports.length > 0 ? (
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
                      return (
                        <tr key={report.id} className="table-row">
                          <td className="table-cell">
                            <div className="flex items-center">
                              <FileText className="h-4 w-4 text-gray-400 mr-2" />
                              <span className="font-medium">{report.name}</span>
                            </div>
                          </td>
                          <td className="table-cell">
                            <span className="text-sm text-gray-600">
                              {engagement?.name || report.engagement_id}
                            </span>
                          </td>
                          <td className="table-cell">
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                              {report.type.toUpperCase()}
                            </span>
                          </td>
                          <td className="table-cell text-sm text-gray-500">
                            {formatDate(report.created_at)}
                          </td>
                          <td className="table-cell">
                            <div className="flex items-center space-x-2">
                              <button
                                onClick={() => handleDownloadReport(report)}
                                className="text-blue-600 hover:text-blue-800"
                                title="Download"
                              >
                                <Download className="h-4 w-4" />
                              </button>
                            </div>
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
                <p className="text-gray-500">No reports found</p>
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
        </div>
      </div>

      {/* Report Modal */}
      {showReportModal && (
        <ReportModal
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
}