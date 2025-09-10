import { useState, useEffect } from 'react';
import { 
  Play, 
  Square, 
  Settings, 
  Clock, 
  FileText, 
  Activity,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Loader
} from 'lucide-react';

interface SchedulerStatus {
  running: boolean;
  active_tasks: number;
  max_concurrent: number;
  auto_generation_enabled: boolean;
  auto_on_completion: boolean;
  batch_generation: boolean;
  schedule?: string;
}

interface ReportHistory {
  id: string;
  engagement_id: string;
  format_type: string;
  trigger_type: string;
  status: string;
  report_path?: string;
  file_size?: number;
  generation_time_seconds?: number;
  created_at: string;
}

const SchedulerPanel = () => {
  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [history, setHistory] = useState<ReportHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    loadSchedulerData();
    // Refresh every 30 seconds
    const interval = setInterval(loadSchedulerData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadSchedulerData = async () => {
    try {
      const [statusResponse, historyResponse] = await Promise.all([
        fetch('/api/v1/scheduler/status'),
        fetch('/api/v1/reports/history?limit=10')
      ]);

      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setStatus(statusData.status);
      }

      if (historyResponse.ok) {
        const historyData = await historyResponse.json();
        setHistory(historyData.history || []);
      }

      setError(null);
    } catch (err: any) {
      console.error('Failed to load scheduler data:', err);
      setError(err.message || 'Failed to load scheduler data');
    } finally {
      setLoading(false);
    }
  };

  const handleSchedulerAction = async (action: 'start' | 'stop') => {
    try {
      setActionLoading(action);
      const response = await fetch(`/api/v1/scheduler/${action}`, {
        method: 'POST'
      });

      if (response.ok) {
        await loadSchedulerData();
      } else {
        const errorData = await response.json();
        setError(errorData.error || `Failed to ${action} scheduler`);
      }
    } catch (err: any) {
      setError(err.message || `Failed to ${action} scheduler`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleBatchGeneration = async () => {
    try {
      setActionLoading('batch');
      const response = await fetch('/api/v1/reports/generate/batch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const result = await response.json();
        // Show success message or notification
        console.log('Batch generation triggered:', result);
        await loadSchedulerData();
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to trigger batch generation');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to trigger batch generation');
    } finally {
      setActionLoading(null);
    }
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return 'N/A';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    return `${seconds.toFixed(1)}s`;
  };

  const getTriggerTypeColor = (type: string) => {
    switch (type) {
      case 'auto_completion': return 'bg-green-100 text-green-800';
      case 'scheduled': return 'bg-blue-100 text-blue-800';
      case 'batch': return 'bg-purple-100 text-purple-800';
      case 'manual': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-center py-8">
          <Loader className="w-6 h-6 animate-spin text-blue-600" />
          <span className="ml-2 text-gray-600">Loading scheduler status...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Settings className="w-5 h-5 text-gray-600 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900">Automatic Report Generation</h3>
          </div>
          <button
            onClick={loadSchedulerData}
            className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-50 border-l-4 border-red-400">
          <div className="flex items-center">
            <AlertCircle className="w-4 h-4 text-red-400 mr-2" />
            <span className="text-red-700">{error}</span>
          </div>
        </div>
      )}

      <div className="p-6">
        {/* Scheduler Status */}
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Scheduler Status</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-50 rounded-lg p-3">
              <div className="flex items-center">
                {status?.running ? (
                  <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                ) : (
                  <Square className="w-4 h-4 text-red-500 mr-2" />
                )}
                <span className="text-sm font-medium">
                  {status?.running ? 'Running' : 'Stopped'}
                </span>
              </div>
            </div>
            
            <div className="bg-gray-50 rounded-lg p-3">
              <div className="flex items-center">
                <Activity className="w-4 h-4 text-blue-500 mr-2" />
                <span className="text-sm font-medium">
                  {status?.active_tasks || 0} Active Tasks
                </span>
              </div>
            </div>
            
            <div className="bg-gray-50 rounded-lg p-3">
              <div className="flex items-center">
                <Clock className="w-4 h-4 text-purple-500 mr-2" />
                <span className="text-sm font-medium">
                  Auto: {status?.auto_on_completion ? 'On' : 'Off'}
                </span>
              </div>
            </div>
            
            <div className="bg-gray-50 rounded-lg p-3">
              <div className="flex items-center">
                <FileText className="w-4 h-4 text-orange-500 mr-2" />
                <span className="text-sm font-medium">
                  Batch: {status?.batch_generation ? 'On' : 'Off'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Control Buttons */}
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-900 mb-3">Controls</h4>
          <div className="flex space-x-3">
            <button
              onClick={() => handleSchedulerAction(status?.running ? 'stop' : 'start')}
              disabled={actionLoading === 'start' || actionLoading === 'stop'}
              className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                status?.running
                  ? 'bg-red-600 hover:bg-red-700 text-white'
                  : 'bg-green-600 hover:bg-green-700 text-white'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {actionLoading === 'start' || actionLoading === 'stop' ? (
                <Loader className="w-4 h-4 animate-spin mr-2" />
              ) : status?.running ? (
                <Square className="w-4 h-4 mr-2" />
              ) : (
                <Play className="w-4 h-4 mr-2" />
              )}
              {status?.running ? 'Stop Scheduler' : 'Start Scheduler'}
            </button>
            
            <button
              onClick={handleBatchGeneration}
              disabled={actionLoading === 'batch'}
              className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {actionLoading === 'batch' ? (
                <Loader className="w-4 h-4 animate-spin mr-2" />
              ) : (
                <FileText className="w-4 h-4 mr-2" />
              )}
              Generate Batch Reports
            </button>
          </div>
        </div>

        {/* Recent Report History */}
        <div>
          <h4 className="text-sm font-medium text-gray-900 mb-3">Recent Report Generation</h4>
          {history.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No report generation history</p>
            </div>
          ) : (
            <div className="space-y-2">
              {history.map((item) => (
                <div key={item.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`px-2 py-1 rounded-full text-xs font-medium ${getTriggerTypeColor(item.trigger_type)}`}>
                      {item.trigger_type.replace('_', ' ')}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{item.engagement_id}</p>
                      <p className="text-xs text-gray-500">
                        {item.format_type.toUpperCase()} • {formatFileSize(item.file_size)} • {formatDuration(item.generation_time_seconds)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {item.status === 'completed' ? (
                      <CheckCircle className="w-4 h-4 text-green-500" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-red-500" />
                    )}
                    <span className="text-xs text-gray-500">
                      {new Date(item.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SchedulerPanel;