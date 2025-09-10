import { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Activity, 
  AlertTriangle, 
  BarChart3, 
  CheckCircle, 
  Clock, 
  Eye, 
  FileText, 
  Play, 
  Plus, 
  RefreshCw, 
  Shield, 
  Square, 
  Target, 
  Trash2,
  Brain,
  Loader,
  ArrowRight,
  X
} from 'lucide-react';
import apiClient, { type Engagement, type Stats, type Activity as ActivityType, type Report } from '../services/apiClient';
import EngagementModal from './EngagementModal';
import ReportModal from './ReportModal';
import { Link } from 'react-router-dom';

interface DashboardProps {
  className?: string;
}

const Dashboard = ({ className = '' }: DashboardProps) => {
  const [stats, setStats] = useState<Stats | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [activities, setActivities] = useState<ActivityType[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEngagementModal, setShowEngagementModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [selectedEngagement, setSelectedEngagement] = useState<Engagement | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [notifications, setNotifications] = useState<Array<{id: string, message: string, type: 'success' | 'info' | 'warning'}>>([]);

  // Load initial data
  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [statsData, engagementsData, activitiesData, reportsData] = await Promise.all([
        apiClient.getStats(),
        apiClient.getEngagements(),
        apiClient.getActivities(),
        apiClient.getReports(),
      ]);
      
      // Check for workflow stage completions and show notifications
      const prevEngagements = engagements;
      if (prevEngagements.length > 0) {
        engagementsData.forEach(engagement => {
          const prevEngagement = prevEngagements.find(e => e.id === engagement.id);
          if (prevEngagement) {
            // Check for stage transitions
            const prevProgress = prevEngagement.progress || '';
            const currentProgress = engagement.progress || '';
            
            // Ensure both progress values are strings before using includes
            if (typeof prevProgress === 'string' && typeof currentProgress === 'string') {
              // Tools finished notification
              if (!prevProgress.includes('Analysis') && currentProgress.includes('Analysis')) {
                addNotification(`Security tools completed for ${engagement.name}`, 'success');
              }
              
              // AI analysis completed notification
              if (!prevProgress.includes('Report') && currentProgress.includes('Report')) {
                addNotification(`AI analysis completed for ${engagement.name}`, 'info');
              }
            }
            
            // Engagement completed notification
            if (prevEngagement.status !== 'completed' && engagement.status === 'completed') {
              addNotification(`Report ready for ${engagement.name}`, 'success');
            }
          }
        });
      }
      
      setStats(statsData);
      setEngagements(engagementsData);
      setActivities(activitiesData.slice(0, 10)); // Show latest 10 activities
      setReports(reportsData.slice(0, 5)); // Show latest 5 reports
    } catch (err: any) {
      console.error('Failed to load dashboard data:', err);
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  };

  const handleCreateEngagement = () => {
    setSelectedEngagement(null);
    setShowEngagementModal(true);
  };

  const handleEditEngagement = (engagement: Engagement) => {
    setSelectedEngagement(engagement);
    setShowEngagementModal(true);
  };

  const handleDeleteEngagement = useCallback(async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this engagement?')) return;
    
    try {
      await apiClient.deleteEngagement(id);
      await refreshData();
    } catch (err: any) {
      console.error('Failed to delete engagement:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to delete engagement');
    }
  }, []);

  const addNotification = useCallback((message: string, type: 'success' | 'info' | 'warning') => {
    const id = Date.now().toString();
    setNotifications(prev => [...prev, { id, message, type }]);
    
    // Auto-remove notification after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const handleStopEngagement = useCallback(async (id: string) => {
    try {
      await apiClient.stopEngagement(id);
      await refreshData();
    } catch (err: any) {
      console.error('Failed to stop engagement:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to stop engagement');
    }
  }, []);



  const getStatusBadge = useMemo(() => {
    const statusConfig = {
      'active': { class: 'badge-info', label: 'Active' },
      'running': { class: 'badge-info', label: 'Running' },
      'completed': { class: 'badge-success', label: 'Completed' },
      'failed': { class: 'badge-danger', label: 'Failed' },
      'stopped': { class: 'badge-warning', label: 'Stopped' },
      'pending': { class: 'badge-gray', label: 'Pending' },
    } as const;

    return (status: string) => {
      const config = statusConfig[status as keyof typeof statusConfig] || { class: 'badge-gray', label: status };
      return (
        <span 
          className={`badge ${config.class}`}
          role="status"
          aria-label={`Status: ${config.label}`}
        >
          {config.label}
        </span>
      );
    };
  }, []);

  const getWorkflowProgress = useCallback((engagement: Engagement) => {
    const progress = engagement.progress || '';
    
    // Determine current stage based on progress text
    let currentStage = 'tools';
    if (typeof progress === 'string') {
      if (progress.includes('Analysis') || progress.includes('AI')) {
        currentStage = 'analysis';
      } else if (progress.includes('Report') || progress.includes('Completed')) {
        currentStage = 'report';
      }
    }
    
    const stages = [
      { id: 'tools', label: 'Security Tools', icon: Target, active: currentStage === 'tools' },
      { id: 'analysis', label: 'AI Analysis', icon: Brain, active: currentStage === 'analysis' },
      { id: 'report', label: 'Report', icon: FileText, active: currentStage === 'report' }
    ];
    
    return (
      <div className="flex items-center space-x-2 mt-1">
        {stages.map((stage, index) => {
          const Icon = stage.icon;
          const isCompleted = engagement.status === 'completed' || 
            (stage.id === 'tools' && (currentStage === 'analysis' || currentStage === 'report')) ||
            (stage.id === 'analysis' && currentStage === 'report');
          const isActive = stage.active && engagement.status === 'running';
          
          return (
            <div key={stage.id} className="flex items-center">
              <div className={`flex items-center space-x-1 text-xs ${
                isCompleted ? 'text-green-600' : 
                isActive ? 'text-blue-600' : 'text-gray-400'
              }`}>
                {isActive ? (
                  <Loader className="h-3 w-3 animate-spin" />
                ) : (
                  <Icon className={`h-3 w-3 ${
                    isCompleted ? 'text-green-600' : 
                    isActive ? 'text-blue-600' : 'text-gray-400'
                  }`} />
                )}
                <span className="hidden sm:inline">{stage.label}</span>
              </div>
              {index < stages.length - 1 && (
                <ArrowRight className="h-2 w-2 text-gray-300 mx-1" />
              )}
            </div>
          );
        })}
      </div>
    );
  }, []);

  const formatDate = useCallback((dateString: string) => {
    try {
      return new Date(dateString).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Invalid date';
    }
  }, []);

  if (loading) {
    return (
      <div className={`flex items-center justify-center min-h-screen ${className}`}>
        <div className="text-center">
          <div className="spinner mx-auto mb-4"></div>
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`flex items-center justify-center min-h-screen ${className}`}>
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Error Loading Dashboard</h2>
          <p className="text-gray-600 mb-4">{error}</p>
          <button onClick={refreshData} className="btn-primary">
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`p-6 max-w-7xl mx-auto ${className}`}>
      {/* Notifications */}
      {notifications.length > 0 && (
        <div className="fixed top-4 right-4 z-50 space-y-2">
          {notifications.map(notification => (
            <div
              key={notification.id}
              className={`flex items-center justify-between p-4 rounded-lg shadow-lg max-w-sm ${
                notification.type === 'success' ? 'bg-green-50 border border-green-200 text-green-800' :
                notification.type === 'info' ? 'bg-blue-50 border border-blue-200 text-blue-800' :
                'bg-yellow-50 border border-yellow-200 text-yellow-800'
              }`}
            >
              <div className="flex items-center space-x-2">
                {notification.type === 'success' && <CheckCircle className="h-4 w-4 text-green-500" />}
                {notification.type === 'info' && <Brain className="h-4 w-4 text-blue-500" />}
                {notification.type === 'warning' && <AlertTriangle className="h-4 w-4 text-yellow-500" />}
                <span className="text-sm font-medium">{notification.message}</span>
              </div>
              <button
                onClick={() => removeNotification(notification.id)}
                className="text-gray-400 hover:text-gray-600 ml-2"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">RedChain</h1>
          <p className="text-gray-600 mt-1">Manage your security engagements and view reports</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={refreshData}
            disabled={refreshing}
            className="btn-outline"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={handleCreateEngagement} className="btn-primary">
            <Plus className="h-4 w-4 mr-2" />
            New Engagement
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Target className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Engagements</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.total_engagements || 0}</p>
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Play className="h-8 w-8 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Active Engagements</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.active_engagements || 0}</p>
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircle className="h-8 w-8 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Completed</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.completed_engagements || 0}</p>
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Shield className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Findings</p>
              <p className="text-2xl font-semibold text-gray-900">{stats?.total_findings || 0}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Engagements Table */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Engagements</h2>
            <button onClick={() => setShowReportModal(true)} className="btn-outline">
              <BarChart3 className="h-4 w-4 mr-2" />
              View All
            </button>
          </div>
          
          <div className="overflow-x-auto">
            <table className="table">
              <thead className="table-header">
                <tr>
                  <th className="table-header-cell">Name</th>
                  <th className="table-header-cell">Target</th>
                  <th className="table-header-cell">Status & Progress</th>
                  <th className="table-header-cell">Actions</th>
                </tr>
              </thead>
              <tbody className="table-body">
                {engagements.slice(0, 5).map((engagement) => (
                  <tr key={engagement.id}>
                    <td className="table-cell font-medium">{engagement.name}</td>
                    <td className="table-cell">{engagement.target}</td>
                    <td className="table-cell">
                      <div className="space-y-1">
                        {getStatusBadge(engagement.status)}
                        {(engagement.status === 'running' || engagement.status === 'active') && getWorkflowProgress(engagement)}
                        {engagement.progress && (
                          <div className="text-xs text-gray-500 truncate max-w-xs">
                            {engagement.progress}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="table-cell">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleEditEngagement(engagement)}
                          className="text-blue-600 hover:text-blue-800"
                          title="Edit"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        {engagement.status === 'active' && (
                          <button
                            onClick={() => handleStopEngagement(engagement.id)}
                            className="text-yellow-600 hover:text-yellow-800"
                            title="Stop"
                          >
                            <Square className="h-4 w-4" />
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteEngagement(engagement.id)}
                          className="text-red-600 hover:text-red-800"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            
            {engagements.length === 0 && (
              <div className="text-center py-8">
                <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No engagements found</p>
                <button onClick={handleCreateEngagement} className="btn-primary mt-4">
                  Create Your First Engagement
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Activity Log */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Activity</h2>
            <Activity className="h-5 w-5 text-gray-400" />
          </div>
          
          <div className="space-y-4">
            {activities.map((activity) => (
              <div key={activity.id} className="flex items-start space-x-3">
                <div className="flex-shrink-0">
                  <div className="h-2 w-2 bg-blue-600 rounded-full mt-2"></div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-900">{activity.action}</p>
                  <p className="text-xs text-gray-500">{formatDate(activity.timestamp)}</p>
                  {activity.details && (
                    <p className="text-xs text-gray-600 mt-1">{activity.details}</p>
                  )}
                </div>
              </div>
            ))}
            
            {activities.length === 0 && (
              <div className="text-center py-8">
                <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">No recent activity</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Reports Section */}
      <div className="card mt-12">
        <div className="card-header">
          <h2 className="card-title">Recent Reports</h2>
          <div className="flex gap-2">
            <button onClick={() => setShowReportModal(true)} className="btn-outline">
              <FileText className="h-4 w-4 mr-2" />
              View All Reports
            </button>
            <Link to="/reports" className="btn-outline">
              <FileText className="h-4 w-4 mr-2" />
              Manage Reports
            </Link>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {reports.map((report) => (
            <div key={report.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium text-gray-900 truncate">{report.name}</h3>
              </div>
              <p className="text-sm text-gray-600 mb-2">{report.type}</p>
              <p className="text-xs text-gray-500">{formatDate(report.created_at)}</p>
            </div>
          ))}
          
          {reports.length === 0 && (
            <div className="col-span-full text-center py-8">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500">No reports available</p>
            </div>
          )}
        </div>
      </div>



      {/* Modals */}
      {showEngagementModal && (
        <EngagementModal
          engagement={selectedEngagement}
          onClose={() => setShowEngagementModal(false)}
          onSave={refreshData}
        />
      )}
      
      {showReportModal && (
        <ReportModal
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
};

export default Dashboard;