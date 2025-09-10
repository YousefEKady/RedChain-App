import { useState, useEffect, useCallback, useRef } from 'react';
import { X, Save, AlertCircle, Target, Brain, FileText, ArrowRight } from 'lucide-react';
import apiClient, { type Engagement, type EngagementData } from '../services/apiClient';

interface EngagementModalProps {
  engagement?: Engagement | null;
  onClose: () => void;
  onSave: () => void;
}

interface FormData {
  name: string;
  target: string;
  scope: string;
  description: string;
}

interface FormErrors {
  name?: string;
  target?: string;
  scope?: string;
  description?: string;
}

const EngagementModal = ({ engagement, onClose, onSave }: EngagementModalProps) => {
  const [formData, setFormData] = useState<FormData>({
    name: '',
    target: '',
    scope: '',
    description: '',
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const [loading, setLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const firstInputRef = useRef<HTMLInputElement>(null);

  const isEditing = !!engagement;

  useEffect(() => {
    if (engagement) {
      setFormData({
        name: engagement.name,
        target: engagement.target,
        scope: engagement.scope,
        description: engagement.description || '',
      });
    } else {
      setFormData({ name: '', target: '', scope: '', description: '' });
    }
    setErrors({});
    setSubmitError(null);
    
    // Focus management
    if (firstInputRef.current) {
      setTimeout(() => firstInputRef.current?.focus(), 100);
    }
  }, [engagement]);

  const validateForm = useCallback((): boolean => {
    const newErrors: FormErrors = {};
    
    // Name validation
    if (!formData.name.trim()) {
      newErrors.name = 'Engagement name is required';
    } else if (formData.name.trim().length < 3) {
      newErrors.name = 'Engagement name must be at least 3 characters';
    } else if (formData.name.trim().length > 100) {
      newErrors.name = 'Engagement name must be less than 100 characters';
    }
    
    // Target validation
    if (!formData.target.trim()) {
      newErrors.target = 'Target is required';
    } else {
      const target = formData.target.trim();
      // Enhanced URL/IP validation
      const urlPattern = /^(https?:\/\/)?(([\da-z\.-]+)\.([a-z\.]{2,6})|((\d{1,3}\.){3}\d{1,3}))(:[\d]+)?([\/?#].*)?$/i;
      const ipPattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+((com|org|net|edu|gov|mil|int|co|io|dev|app|tech|info|biz|name|pro))$/i;
      
      if (!urlPattern.test(target) && !ipPattern.test(target) && !domainPattern.test(target)) {
        newErrors.target = 'Please enter a valid URL, IP address, or domain name';
      }
    }
    
    // Scope validation
    if (!formData.scope.trim()) {
      newErrors.scope = 'Scope is required';
    } else if (formData.scope.trim().length < 10) {
      newErrors.scope = 'Scope must be at least 10 characters';
    }
    
    // Description validation (optional but if provided, should be meaningful)
    if (formData.description && formData.description.trim().length > 0 && formData.description.trim().length < 10) {
      newErrors.description = 'Description must be at least 10 characters if provided';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }, [formData]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error for this field when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors(prev => ({ ...prev, [name]: undefined }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setSubmitError(null);

    try {
      const engagementData: EngagementData = {
        name: formData.name.trim(),
        target: formData.target.trim(),
        scope: formData.scope.trim(),
        ...(formData.description.trim() && { description: formData.description.trim() }),
      };

      if (isEditing && engagement) {
        await apiClient.updateEngagement(engagement.id, engagementData);
      } else {
        await apiClient.createEngagement(engagementData);
      }

      onSave();
      onClose();
    } catch (error: any) {
      console.error('Failed to save engagement:', error);
      setSubmitError(error.response?.data?.detail || error.message || 'Failed to save engagement');
    } finally {
      setLoading(false);
    }
  };

  const handleBackdropClick = useCallback((e: React.MouseEvent) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  }, [onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  }, [onClose]);

  return (
    <div 
      className="modal-overlay" 
      onClick={handleBackdropClick} 
      onKeyDown={handleKeyDown}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div className="modal-container" ref={modalRef}>
        <div className="modal-content">
          <div className="modal-panel">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-200">
              <h3 id="modal-title" className="text-lg font-medium text-gray-900">
                {isEditing ? 'Edit Engagement' : 'Create New Engagement'}
              </h3>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-600 transition-colors"
                aria-label="Close modal"
                type="button"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            {/* Workflow Overview */}
            {!isEditing && (
              <div className="px-6 py-4 bg-blue-50 border-b border-blue-200">
                <h4 className="text-sm font-medium text-blue-900 mb-3">Engagement Workflow</h4>
                <div className="flex items-center justify-between text-xs text-blue-700">
                  <div className="flex items-center">
                    <Target className="h-4 w-4 mr-1" />
                    <span>Security Tools</span>
                  </div>
                  <ArrowRight className="h-3 w-3 text-blue-400" />
                  <div className="flex items-center">
                    <Brain className="h-4 w-4 mr-1" />
                    <span>AI Analysis</span>
                  </div>
                  <ArrowRight className="h-3 w-3 text-blue-400" />
                  <div className="flex items-center">
                    <FileText className="h-4 w-4 mr-1" />
                    <span>Report Generation</span>
                  </div>
                </div>
                <p className="text-xs text-blue-600 mt-2">
                  Your engagement will automatically run security tools, analyze results with AI, and generate a comprehensive report.
                </p>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="p-6">
              {submitError && (
                <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
                  <div className="flex items-center">
                    <AlertCircle className="h-5 w-5 text-red-400 mr-2" />
                    <span className="text-sm text-red-700">{submitError}</span>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                {/* Engagement Name */}
                <div>
                  <label htmlFor="name" className="form-label">
                    Engagement Name *
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className={`form-input ${
                      errors.name ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
                    }`}
                    placeholder="e.g., Web Application Security Assessment"
                    disabled={loading}
                    ref={firstInputRef}
                    aria-required="true"
                    aria-invalid={!!errors.name}
                    aria-describedby={errors.name ? 'name-error' : undefined}
                  />
                  {errors.name && <p id="name-error" className="form-error" role="alert">{errors.name}</p>}
                </div>

                {/* Target */}
                <div>
                  <label htmlFor="target" className="form-label">
                    Target *
                  </label>
                  <input
                    type="text"
                    id="target"
                    name="target"
                    value={formData.target}
                    onChange={handleInputChange}
                    className={`form-input ${
                      errors.target ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
                    }`}
                    placeholder="e.g., https://example.com or 192.168.1.100"
                    disabled={loading}
                    aria-required="true"
                    aria-invalid={!!errors.target}
                    aria-describedby={errors.target ? 'target-error' : undefined}
                  />
                  {errors.target && <p id="target-error" className="form-error" role="alert">{errors.target}</p>}
                  <p className="text-xs text-gray-500 mt-1">
                    Enter the target URL or IP address for the security assessment
                  </p>
                </div>

                {/* Scope */}
                <div>
                  <label htmlFor="scope" className="form-label">
                    Scope *
                  </label>
                  <textarea
                    id="scope"
                    name="scope"
                    value={formData.scope}
                    onChange={handleInputChange}
                    rows={3}
                    className={`form-input ${
                      errors.scope ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
                    }`}
                    placeholder="Define the scope of the engagement (e.g., specific URLs, IP ranges, excluded areas)"
                    disabled={loading}
                    aria-required="true"
                    aria-invalid={!!errors.scope}
                    aria-describedby={errors.scope ? 'scope-error' : undefined}
                  />
                  {errors.scope && <p id="scope-error" className="form-error" role="alert">{errors.scope}</p>}
                  <p className="text-xs text-gray-500 mt-1">
                    Clearly define what is included and excluded from the assessment
                  </p>
                </div>

                {/* Description */}
                <div>
                  <label htmlFor="description" className="form-label">
                    Description
                  </label>
                  <textarea
                    id="description"
                    name="description"
                    value={formData.description}
                    onChange={handleInputChange}
                    rows={3}
                    className="form-input"
                    placeholder="Additional details about the engagement (optional)"
                    disabled={loading}
                    aria-invalid={!!errors.description}
                    aria-describedby={errors.description ? 'description-error' : undefined}
                  />
                  {errors.description && <p id="description-error" className="form-error" role="alert">{errors.description}</p>}
                  <p className="text-xs text-gray-500 mt-1">
                    Optional: Add any additional context or requirements for this engagement
                  </p>
                </div>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={onClose}
                  className="btn-outline"
                  disabled={loading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <div className="spinner mr-2"></div>
                      {isEditing ? 'Updating...' : 'Creating...'}
                    </>
                  ) : (
                    <>
                      <Save className="h-4 w-4 mr-2" />
                      {isEditing ? 'Update Engagement' : 'Create Engagement'}
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EngagementModal;