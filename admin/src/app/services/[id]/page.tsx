'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { Server, Zap } from 'lucide-react';
import { fortressGet, fortressPut, fortressDelete } from '@/lib/api';
import { ServiceConfig } from '@/lib/types';
import { PROTECTION_LEVELS_LIST } from '@/lib/constants';

interface ServiceFormData {
  name: string;
  domains: string;
  upstream_address: string;
  protection_level_override: string;
  rate_limit_multiplier: string;
  max_connections: string;
  connect_timeout_ms: string;
  response_timeout_ms: string;
}

function serviceToForm(service: ServiceConfig): ServiceFormData {
  return {
    name: service.name,
    domains: service.domains.join(', '),
    upstream_address: service.upstream_address,
    protection_level_override:
      service.protection_level_override === null
        ? ''
        : String(service.protection_level_override),
    rate_limit_multiplier: String(service.rate_limit_multiplier),
    max_connections: String(service.max_connections),
    connect_timeout_ms: String(service.connect_timeout_ms),
    response_timeout_ms: String(service.response_timeout_ms),
  };
}

export default function ServiceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [service, setService] = useState<ServiceConfig | null>(null);
  const [formData, setFormData] = useState<ServiceFormData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [challengeToggling, setChallengeToggling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const fetchService = useCallback(async () => {
    try {
      setError(null);
      const data = await fortressGet<ServiceConfig>(
        `/api/fortress/services/${id}`
      );
      setService(data);
      setFormData(serviceToForm(data));
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to load service configuration.'
      );
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchService();
  }, [fetchService]);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => (prev ? { ...prev, [name]: value } : prev));
    setSuccess(false);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData) return;

    setSaving(true);
    setError(null);
    setSuccess(false);

    try {
      const payload = {
        name: formData.name.trim(),
        domains: formData.domains
          .split(',')
          .map((d) => d.trim())
          .filter(Boolean),
        upstream_address: formData.upstream_address.trim(),
        protection_level_override:
          formData.protection_level_override === ''
            ? null
            : Number(formData.protection_level_override),
        rate_limit_multiplier: Number(formData.rate_limit_multiplier),
        max_connections: Number(formData.max_connections),
        connect_timeout_ms: Number(formData.connect_timeout_ms),
        response_timeout_ms: Number(formData.response_timeout_ms),
      };

      await fortressPut(
        `/api/fortress/services/${id}`,
        payload
      );
      // Refetch to get the latest data
      const refreshed = await fortressGet<ServiceConfig>(`/api/fortress/services/${id}`);
      setService(refreshed);
      setFormData(serviceToForm(refreshed));
      setSuccess(true);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to update service configuration.'
      );
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    setError(null);

    try {
      await fortressDelete(`/api/fortress/services/${id}`);
      router.push('/services');
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to delete service.'
      );
      setDeleting(false);
      setConfirmDelete(false);
    }
  };

  const handleChallengeToggle = async () => {
    if (!service) return;
    setChallengeToggling(true);
    setError(null);

    try {
      await fortressPut(`/api/fortress/services/${id}`, {
        ...service,
        always_challenge: !service.always_challenge,
      });
      const refreshed = await fortressGet<ServiceConfig>(`/api/fortress/services/${id}`);
      setService(refreshed);
      setFormData(serviceToForm(refreshed));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle JS Challenge.');
    } finally {
      setChallengeToggling(false);
    }
  };

  const getProtectionLabel = (level: number | null): string => {
    if (level === null) return 'Inherit Global DEFCON';
    const found = PROTECTION_LEVELS_LIST.find((pl) => pl.level === level);
    return found ? `${found.label} - ${found.name}` : `Level ${level}`;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-zinc-100 p-6 md:p-10 flex items-center justify-center">
        <div className="text-zinc-500">Loading service configuration...</div>
      </div>
    );
  }

  if (error && !service) {
    return (
      <div className="min-h-screen bg-black text-zinc-100 p-6 md:p-10">
        <div className="max-w-3xl mx-auto">
          <Link
            href="/services"
            className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 mb-6 transition-colors"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 19l-7-7 7-7"
              />
            </svg>
            Back to Services
          </Link>
          <div className="rounded-xl border border-red-800 bg-red-900/30 p-5 text-sm text-red-300">
            {error}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 md:p-10">
      <div className="max-w-3xl mx-auto">
        {/* Back Link */}
        <Link
          href="/services"
          className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 mb-6 transition-colors"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15 19l-7-7 7-7"
            />
          </svg>
          Back to Services
        </Link>

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center">
              <Server className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-zinc-100">
                Service Configuration
              </h1>
              <p className="text-sm text-zinc-500 mt-0.5 font-mono">{service?.name} &mdash; {service?.id}</p>
            </div>
          </div>
          <span
            className={`inline-flex items-center gap-1.5 text-xs font-medium rounded-full px-2.5 py-0.5 ${
              service?.enabled
                ? 'text-emerald-400 bg-emerald-400/10 border border-emerald-400/20'
                : 'text-zinc-500 bg-zinc-800 border border-zinc-700'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                service?.enabled ? 'bg-emerald-400' : 'bg-zinc-500'
              }`}
            />
            {service?.enabled ? 'Active' : 'Inactive'}
          </span>
        </div>

        {/* Service Info Card */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 mb-6">
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">
            Current Configuration
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-zinc-500">Origin Server</span>
              <p className="text-zinc-100 font-mono text-xs mt-0.5">
                {service?.upstream_address}
              </p>
            </div>
            <div>
              <span className="text-zinc-500">Protection Level</span>
              <p className="text-zinc-100 mt-0.5">
                {getProtectionLabel(service?.protection_level_override ?? null)}
              </p>
            </div>
            <div>
              <span className="text-zinc-500">Rate Limit Coefficient</span>
              <p className="text-zinc-100 mt-0.5">
                {service?.rate_limit_multiplier}x
              </p>
            </div>
            <div>
              <span className="text-zinc-500">Max Concurrent Connections</span>
              <p className="text-zinc-100 mt-0.5">
                {service?.max_connections}
              </p>
            </div>
            <div>
              <span className="text-zinc-500">Connect Timeout</span>
              <p className="text-zinc-100 mt-0.5">
                {service?.connect_timeout_ms} ms
              </p>
            </div>
            <div>
              <span className="text-zinc-500">Response Timeout</span>
              <p className="text-zinc-100 mt-0.5">
                {service?.response_timeout_ms} ms
              </p>
            </div>
          </div>

          {/* Domains */}
          <div className="mt-4 pt-4 border-t border-zinc-800">
            <span className="text-zinc-500 text-sm">Protected Domains</span>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {service?.domains.map((domain) => (
                <span
                  key={domain}
                  className="inline-block bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs rounded-md px-2.5 py-1"
                >
                  {domain}
                </span>
              ))}
            </div>
          </div>

          {/* JS Challenge Toggle */}
          <div className="mt-4 pt-4 border-t border-zinc-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className={`w-4 h-4 ${service?.always_challenge ? 'text-yellow-400' : 'text-zinc-500'}`} />
                <div>
                  <span className="text-sm font-medium text-zinc-200">JS Challenge (PoW)</span>
                  <p className="text-xs text-zinc-500 mt-0.5">
                    {service?.always_challenge
                      ? 'All visitors must solve a proof-of-work challenge'
                      : 'Challenge only triggered by threat score thresholds'}
                  </p>
                </div>
              </div>
              <button
                onClick={handleChallengeToggle}
                disabled={challengeToggling}
                className="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50"
                style={{
                  backgroundColor: service?.always_challenge
                    ? 'rgb(234 179 8)'
                    : 'rgb(63 63 70)',
                }}
                title={service?.always_challenge ? 'Disable JS Challenge' : 'Enable JS Challenge'}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    service?.always_challenge ? 'translate-x-[22px]' : 'translate-x-[3px]'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Alerts */}
        {error && (
          <div className="mb-6 rounded-xl border border-red-800 bg-red-900/30 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {success && (
          <div className="mb-6 rounded-xl border border-emerald-800 bg-emerald-900/30 p-4 text-sm text-emerald-300">
            Service configuration saved successfully.
          </div>
        )}

        {/* Edit Form */}
        {formData && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">
              Edit Configuration
            </h2>
            <form onSubmit={handleSave} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Name */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Service Identifier
                  </label>
                  <input
                    type="text"
                    name="name"
                    required
                    value={formData.name}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Upstream */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Origin Server
                  </label>
                  <input
                    type="text"
                    name="upstream_address"
                    required
                    value={formData.upstream_address}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Domains */}
                <div className="md:col-span-2">
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Protected Domains
                    <span className="text-zinc-600 ml-1">(comma separated)</span>
                  </label>
                  <input
                    type="text"
                    name="domains"
                    required
                    value={formData.domains}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Protection Level Override */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Protection Level Override
                  </label>
                  <select
                    name="protection_level_override"
                    value={formData.protection_level_override}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  >
                    <option value="">Inherit Global DEFCON</option>
                    {PROTECTION_LEVELS_LIST.map((pl) => (
                      <option key={pl.level} value={pl.level}>
                        {pl.label} - {pl.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Rate Limit Multiplier */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Rate Limit Coefficient
                  </label>
                  <input
                    type="number"
                    name="rate_limit_multiplier"
                    required
                    min="0.1"
                    step="0.1"
                    value={formData.rate_limit_multiplier}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Max Connections */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Max Concurrent Connections
                  </label>
                  <input
                    type="number"
                    name="max_connections"
                    required
                    min="1"
                    value={formData.max_connections}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Connect Timeout */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Connect Timeout (ms)
                  </label>
                  <input
                    type="number"
                    name="connect_timeout_ms"
                    required
                    min="100"
                    value={formData.connect_timeout_ms}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>

                {/* Response Timeout */}
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">
                    Response Timeout (ms)
                  </label>
                  <input
                    type="number"
                    name="response_timeout_ms"
                    required
                    min="100"
                    value={formData.response_timeout_ms}
                    onChange={handleInputChange}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-zinc-100 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                  />
                </div>
              </div>

              <div className="flex justify-between items-center pt-4 border-t border-zinc-800">
                {/* Delete Service */}
                <div>
                  {confirmDelete ? (
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-red-400">Permanently delete this service?</span>
                      <button
                        type="button"
                        onClick={handleDelete}
                        disabled={deleting}
                        className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 text-xs font-medium transition-colors"
                      >
                        {deleting ? 'Deleting...' : 'Confirm Delete'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmDelete(false)}
                        className="text-zinc-400 hover:text-zinc-200 text-xs px-2 py-1.5 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmDelete(true)}
                      className="text-sm text-red-400 hover:text-red-300 transition-colors px-3 py-1.5 rounded hover:bg-red-900/20"
                    >
                      Delete Service
                    </button>
                  )}
                </div>

                {/* Save / Reset */}
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      if (service) {
                        setFormData(serviceToForm(service));
                        setSuccess(false);
                        setError(null);
                      }
                    }}
                    className="text-sm text-zinc-400 hover:text-zinc-200 transition-colors px-4 py-2"
                  >
                    Reset
                  </button>
                  <button
                    type="submit"
                    disabled={saving}
                    className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg px-5 py-2 text-sm font-medium transition-colors"
                  >
                    {saving ? 'Saving...' : 'Save Configuration'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}
