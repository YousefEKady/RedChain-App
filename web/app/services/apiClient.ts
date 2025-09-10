import axios, { type AxiosInstance, type AxiosResponse } from 'axios';

interface ApiResponse<T = any> {
  data: T;
  message?: string;
  status: string;
}

interface EngagementData {
  name: string;
  target: string;
  scope: string;
  description?: string;
}

export interface Engagement {
  id: string;
  name: string;
  target: string;
  scope: string;
  status: string;
  created_at: string;
  description?: string;
  progress?: string;
  findings_count?: number;
}

interface Stats {
  total_engagements: number;
  active_engagements: number;
  completed_engagements: number;
  total_findings: number;
}

interface Activity {
  id: string;
  engagement_id: string;
  action: string;
  timestamp: string;
  details?: string;
}

interface Report {
  id: string;
  engagement_id: string;
  name: string;
  type: string;
  created_at: string;
  file_path?: string;
}

class ApiClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor() {
    // Determine base URL based on environment
    if (typeof window !== 'undefined') {
      // Client-side: use current host with backend port
      const protocol = window.location.protocol;
      const hostname = window.location.hostname;
      const apiPort = '8000'; // Backend runs on port 8000
      this.baseURL = `${protocol}//${hostname}:${apiPort}/api/v1`;
    } else {
      // Fallback for server-side rendering
      this.baseURL = 'http://127.0.0.1:8000/api/v1';
    }
    
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor for debugging
    this.client.interceptors.request.use(
      (config) => {
        console.log(`[API] ${config.method?.toUpperCase()} ${config.url}`, {
          headers: config.headers,
          data: config.data,
        });
        return config;
      },
      (error) => {
        console.error('[API] Request error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for debugging and error handling
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        if (process.env.NODE_ENV === 'development') {
          console.log(`[API] Response ${response.status}:`, response.data);
        }
        return response;
      },
      (error) => {
        const errorInfo = {
          status: error.response?.status,
          data: error.response?.data,
          message: error.message,
          url: error.config?.url,
        };
        
        if (process.env.NODE_ENV === 'development') {
          console.error('[API] Response error:', errorInfo);
        }
        
        // Handle specific error cases
        if (error.response?.status === 401) {
          // Handle unauthorized access
          console.warn('Unauthorized access detected');
        } else if (error.response?.status >= 500) {
          // Handle server errors
          console.error('Server error detected:', errorInfo);
        }
        
        // Create a more user-friendly error message
        const userMessage = this.getUserFriendlyErrorMessage(error);
        const enhancedError = new Error(userMessage);
        (enhancedError as any).originalError = error;
        (enhancedError as any).response = error.response;
        
        return Promise.reject(enhancedError);
      }
    );
  }

  getUserFriendlyErrorMessage(error: any): string {
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
      return 'Unable to connect to the server. Please check your connection and try again.';
    }
    
    if (error.response?.status === 400) {
      return error.response.data?.detail || 'Invalid request. Please check your input and try again.';
    }
    
    if (error.response?.status === 401) {
      return 'Authentication required. Please log in and try again.';
    }
    
    if (error.response?.status === 403) {
      return 'You do not have permission to perform this action.';
    }
    
    if (error.response?.status === 404) {
      return 'The requested resource was not found.';
    }
    
    if (error.response?.status >= 500) {
      return 'A server error occurred. Please try again later.';
    }
    
    return error.response?.data?.detail || error.message || 'An unexpected error occurred.';
  }

  // Health check
  async healthCheck(): Promise<ApiResponse> {
    const response = await this.client.get('/health');
    return response.data;
  }

  // Stats endpoints
  async getStats(): Promise<Stats> {
    const response = await this.client.get('/system/stats');
    return response.data;
  }

  // Engagement endpoints
  async getEngagements(): Promise<Engagement[]> {
    const response = await this.client.get('/engagements');
    return response.data;
  }

  async getEngagement(id: string): Promise<Engagement> {
    const response = await this.client.get(`/engagements/${id}`);
    return response.data;
  }

  async createEngagement(data: EngagementData): Promise<Engagement> {
    const response = await this.client.post('/engagements/start', data);
    return response.data;
  }

  async updateEngagement(id: string, data: Partial<EngagementData>): Promise<Engagement> {
    const response = await this.client.put(`/engagements/${id}`, data);
    return response.data;
  }

  async deleteEngagement(id: string): Promise<ApiResponse> {
    const response = await this.client.delete(`/engagements/${id}`);
    return response.data;
  }

  async stopEngagement(id: string): Promise<ApiResponse> {
    const response = await this.client.post(`/engagements/${id}/stop`);
    return response.data;
  }

  // Activity endpoints
  async getActivities(engagementId?: string): Promise<Activity[]> {
    const url = engagementId ? `/activity?engagement_id=${engagementId}` : '/activity';
    const response = await this.client.get(url);
    return response.data;
  }

  // Reports endpoints
  async getReports(engagementId?: string): Promise<Report[]> {
    const url = engagementId ? `/reports?engagement_id=${engagementId}` : '/reports';
    const response = await this.client.get(url);
    return response.data;
  }

  async generateReport(engagementId: string, reportType: string = 'html', useAi: boolean = true): Promise<Report> {
    const response = await this.client.post('/reports/generate', {
      engagement_id: engagementId,
      format: reportType,
      use_ai: useAi,
    });
    return response.data;
  }

  async downloadReport(reportId: string, format: string = 'html'): Promise<Blob> {
    const response = await this.client.get(`/reports/${reportId}_${format}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  // System endpoints
  async getSystemInfo(): Promise<any> {
    const response = await this.client.get('/system/info');
    return response.data;
  }

  async getSystemStats(): Promise<any> {
    const response = await this.client.get('/system/stats');
    return response.data;
  }

  // Utility methods
  getBaseURL(): string {
    return this.baseURL;
  }

  // Test connection
  async testConnection(): Promise<boolean> {
    try {
      await this.healthCheck();
      return true;
    } catch (error) {
      console.error('Connection test failed:', error);
      return false;
    }
  }
}

// Create and export a singleton instance
const apiClient = new ApiClient();
export default apiClient;

// Export types for use in components
export type {
  ApiResponse,
  EngagementData,
  Stats,
  Activity,
  Report,
};