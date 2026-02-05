'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { Server, Zap } from 'lucide-react';
import { fortressGet, fortressPost, fortressPut, fortressDelete } from '@/lib/api';
import { ServiceConfig } from '@/lib/types';
import { PROTECTION_LEVELS_LIST, formatNumber } from '@/lib/constants';

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

const emptyForm: ServiceFormData = {
  name: '',
  domains: '',
  upstream_address: '',
  protection_level_override: '',
  rate_limit_multiplier: '1',
  max_connections: '1000',
  connect_timeout_ms: '5000',
  response_timeout_ms: '30000',
};

export default function ServicesPage() {
  const [services, setServices] = useState<ServiceConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState<ServiceFormData>(emptyForm);
  const [submitting, setSubmitting] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [challengeTogglingId, setChallengeTogglingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchServices = useCallback(async () => {
    try {
      setError(null);
      const data = await fortressGet<ServiceConfig[]>('/api/fortress/services');
      setServices(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load services.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchServices();
  }, [fetchServices]);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

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

      await fortressPost('/api/fortress/services', payload);
      setFormData(emptyForm);
      setShowForm(false);
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register service.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggle = async (id: string) => {
    setTogglingId(id);
    setError(null);

    try {
      await fortressPost(`/api/fortress/services/${id}/toggle`, {});
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle service status.');
    } finally {
      setTogglingId(null);
    }
  };

  const handleChallengeToggle = async (service: ServiceConfig) => {
    setChallengeTogglingId(service.id);
    setError(null);

    try {
      await fortressPut(`/api/fortress/services/${service.id}`, {
        ...service,
        always_challenge: !service.always_challenge,
      });
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle JS Challenge.');
    } finally {
      setChallengeTogglingId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    setError(null);

    try {
      await fortressDelete(`/api/fortress/services/${id}`);
      setConfirmDeleteId(null);
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove service.');
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 md:p-10">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center">
            <Server className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Protected Services</h1>
            <p className="text-sm text-zinc-500 mt-0.5">
              Service registration and domain-level protection management
            </p>
          </div>
        </div>
        <button
          onClick={() => {
            setFormData(emptyForm);
            setShowForm((prev) => !prev);
          }}
          className="bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
        >
          {showForm ? 'Cancel' : 'Register Service'}
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="mb-6 rounded-xl border border-red-800 bg-red-900/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Create Form */}
      {showForm && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 mb-8">
          <h2 className="text-lg font-semibold text-zinc-100 mb-4">
            Register New Service
          </h2>
          <form onSubmit={handleCreate} className="space-y-4">
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
                  placeholder="my-service"
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
                  placeholder="http://127.0.0.1:8080"
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
                  placeholder="example.com, www.example.com, api.example.com"
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

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="mr-3 text-sm text-zinc-400 hover:text-zinc-200 transition-colors px-4 py-2"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg px-5 py-2 text-sm font-medium transition-colors"
              >
                {submitting ? 'Deploying...' : 'Deploy Service'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Services Table */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-zinc-500">Loading services...</div>
        ) : services.length === 0 ? (
          <div className="p-10 text-center text-zinc-500">
            No services registered yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-zinc-500 border-b border-zinc-800 text-left">
                  <th className="px-5 py-3 font-medium">Service</th>
                  <th className="px-5 py-3 font-medium">Domains</th>
                  <th className="px-5 py-3 font-medium">Origin</th>
                  <th className="px-5 py-3 font-medium">Status</th>
                  <th className="px-5 py-3 font-medium">JS Challenge</th>
                  <th className="px-5 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {services.map((service) => (
                  <tr
                    key={service.id}
                    className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors"
                  >
                    {/* Name */}
                    <td className="px-5 py-3">
                      <Link
                        href={`/services/${service.id}`}
                        className="text-zinc-100 hover:text-blue-400 font-medium transition-colors"
                      >
                        {service.name}
                      </Link>
                    </td>

                    {/* Domains */}
                    <td className="px-5 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {service.domains.map((domain) => (
                          <span
                            key={domain}
                            className="inline-block bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs rounded-md px-2 py-0.5"
                          >
                            {domain}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Upstream */}
                    <td className="px-5 py-3">
                      <span className="text-zinc-400 font-mono text-xs">
                        {service.upstream_address}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-5 py-3">
                      {service.enabled ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 rounded-full px-2.5 py-0.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-zinc-500 bg-zinc-800 border border-zinc-700 rounded-full px-2.5 py-0.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
                          Inactive
                        </span>
                      )}
                    </td>

                    {/* JS Challenge */}
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleChallengeToggle(service)}
                          disabled={challengeTogglingId === service.id}
                          className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50"
                          style={{
                            backgroundColor: service.always_challenge
                              ? 'rgb(234 179 8)'
                              : 'rgb(63 63 70)',
                          }}
                          title={service.always_challenge ? 'Disable JS Challenge' : 'Enable JS Challenge'}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              service.always_challenge ? 'translate-x-[18px]' : 'translate-x-[3px]'
                            }`}
                          />
                        </button>
                        {service.always_challenge && (
                          <Zap className="w-3.5 h-3.5 text-yellow-400" />
                        )}
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-2">
                        {/* Edit Link */}
                        <Link
                          href={`/services/${service.id}`}
                          className="text-zinc-400 hover:text-blue-400 text-xs font-medium transition-colors px-2 py-1 rounded hover:bg-zinc-800"
                        >
                          Configure
                        </Link>

                        {/* Toggle */}
                        <button
                          onClick={() => handleToggle(service.id)}
                          disabled={togglingId === service.id}
                          className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50"
                          style={{
                            backgroundColor: service.enabled
                              ? 'rgb(34 197 94)'
                              : 'rgb(63 63 70)',
                          }}
                          title={service.enabled ? 'Disable service' : 'Enable service'}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              service.enabled ? 'translate-x-[18px]' : 'translate-x-[3px]'
                            }`}
                          />
                        </button>

                        {/* Delete */}
                        {confirmDeleteId === service.id ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleDelete(service.id)}
                              disabled={deletingId === service.id}
                              className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg px-2 py-1 text-xs font-medium transition-colors"
                            >
                              {deletingId === service.id ? '...' : 'Confirm'}
                            </button>
                            <button
                              onClick={() => setConfirmDeleteId(null)}
                              className="text-zinc-400 hover:text-zinc-200 text-xs px-2 py-1 transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmDeleteId(service.id)}
                            className="text-zinc-500 hover:text-red-400 text-xs font-medium transition-colors px-2 py-1 rounded hover:bg-zinc-800"
                          >
                            Remove
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Summary */}
      {!loading && services.length > 0 && (
        <div className="mt-4 text-xs text-zinc-600 text-right">
          {formatNumber(services.length)} registered {services.length === 1 ? 'service' : 'services'}
        </div>
      )}
    </div>
  );
}
