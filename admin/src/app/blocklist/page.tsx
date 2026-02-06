'use client';

import { useCallback, useEffect, useState } from 'react';
import { fortressGet, fortressPost, fortressDelete } from '@/lib/api';
import type { BlockedIp, BlockedAsn, BlockedCountry } from '@/lib/types';
import {
  Shield,
  Plus,
  X,
  Trash2,
  Network,
  Globe,
  Hash,
  Save,
  AlertTriangle,
  Ban,
} from 'lucide-react';
import { CountryFlag } from '@/components/country-flag';

type Tab = 'ip' | 'asn' | 'country';

export default function BlocklistPage() {
  const [activeTab, setActiveTab] = useState<Tab>('ip');

  // --------------- IP state ---------------
  const [ips, setIps] = useState<BlockedIp[]>([]);
  const [ipLoading, setIpLoading] = useState(false);
  const [showIpForm, setShowIpForm] = useState(false);
  const [ipForm, setIpForm] = useState({ ip: '', reason: '', ttl: '' });

  // --------------- ASN state ---------------
  const [asns, setAsns] = useState<BlockedAsn[]>([]);
  const [asnLoading, setAsnLoading] = useState(false);
  const [showAsnForm, setShowAsnForm] = useState(false);
  const [asnForm, setAsnForm] = useState({ asn: '', reason: '' });

  // --------------- Country state ---------------
  const [countries, setCountries] = useState<BlockedCountry[]>([]);
  const [countryLoading, setCountryLoading] = useState(false);
  const [showCountryForm, setShowCountryForm] = useState(false);
  const [countryForm, setCountryForm] = useState({ code: '', reason: '' });

  // --------------- Fetchers ---------------
  const fetchIps = useCallback(async () => {
    setIpLoading(true);
    try {
      const data = await fortressGet<{ entries: BlockedIp[] }>('/api/fortress/blocklist?type=ip');
      setIps(data.entries);
    } catch (err) {
      console.error('Failed to fetch IP blocklist', err);
    } finally {
      setIpLoading(false);
    }
  }, []);

  const fetchAsns = useCallback(async () => {
    setAsnLoading(true);
    try {
      const data = await fortressGet<{ entries: BlockedAsn[] }>('/api/fortress/blocklist?type=asn');
      setAsns(data.entries);
    } catch (err) {
      console.error('Failed to fetch ASN blocklist', err);
    } finally {
      setAsnLoading(false);
    }
  }, []);

  const fetchCountries = useCallback(async () => {
    setCountryLoading(true);
    try {
      const data = await fortressGet<{ entries: BlockedCountry[] }>('/api/fortress/blocklist?type=country');
      setCountries(data.entries);
    } catch (err) {
      console.error('Failed to fetch country restrictions', err);
    } finally {
      setCountryLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'ip') fetchIps();
    else if (activeTab === 'asn') fetchAsns();
    else fetchCountries();
  }, [activeTab, fetchIps, fetchAsns, fetchCountries]);

  // --------------- Add handlers ---------------
  const addIp = async () => {
    if (!ipForm.ip) return;
    try {
      await fortressPost('/api/fortress/blocklist', {
        value: ipForm.ip,
        type: 'ip',
        reason: ipForm.reason,
        ttl_secs: ipForm.ttl ? Number(ipForm.ttl) : undefined,
      });
      setIpForm({ ip: '', reason: '', ttl: '' });
      setShowIpForm(false);
      fetchIps();
    } catch (err) {
      console.error('Failed to add IP to blocklist', err);
    }
  };

  const addAsn = async () => {
    if (!asnForm.asn) return;
    try {
      await fortressPost('/api/fortress/blocklist', {
        value: String(asnForm.asn),
        type: 'asn',
        reason: asnForm.reason,
      });
      setAsnForm({ asn: '', reason: '' });
      setShowAsnForm(false);
      fetchAsns();
    } catch (err) {
      console.error('Failed to add ASN to blocklist', err);
    }
  };

  const addCountry = async () => {
    if (!countryForm.code) return;
    try {
      await fortressPost('/api/fortress/blocklist', {
        value: countryForm.code,
        type: 'country',
        reason: countryForm.reason,
      });
      setCountryForm({ code: '', reason: '' });
      setShowCountryForm(false);
      fetchCountries();
    } catch (err) {
      console.error('Failed to add country restriction', err);
    }
  };

  // --------------- Delete handlers ---------------
  const deleteIp = async (id: number) => {
    if (!confirm('Remove this IP from the blocklist?')) return;
    try {
      await fortressDelete('/api/fortress/blocklist/' + id + '?type=ip');
      fetchIps();
    } catch (err) {
      console.error('Failed to remove IP entry', err);
    }
  };

  const deleteAsn = async (id: number) => {
    if (!confirm('Remove this ASN from the blocklist?')) return;
    try {
      await fortressDelete('/api/fortress/blocklist/' + id + '?type=asn');
      fetchAsns();
    } catch (err) {
      console.error('Failed to remove ASN entry', err);
    }
  };

  const deleteCountry = async (id: number) => {
    if (!confirm('Remove this geographic restriction?')) return;
    try {
      await fortressDelete('/api/fortress/blocklist/' + id + '?type=country');
      fetchCountries();
    } catch (err) {
      console.error('Failed to remove country restriction', err);
    }
  };

  // --------------- Shared styles ---------------
  const tabClass = (tab: Tab) => {
    const isActive = activeTab === tab;
    return `flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium cursor-pointer transition-all ${
      isActive
        ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
        : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50 border border-transparent'
    }`;
  };

  const inputClass =
    'bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-100 w-full focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 placeholder:text-zinc-600 transition-colors';

  const primaryBtn =
    'inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-2.5 text-sm font-medium transition-colors';

  const dangerBtn =
    'inline-flex items-center gap-1 bg-red-600/10 text-red-400 hover:bg-red-600/20 border border-red-500/20 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors';

  const secondaryBtn =
    'inline-flex items-center gap-2 border border-zinc-700 bg-zinc-800 text-zinc-300 hover:bg-zinc-700 hover:text-white rounded-lg px-4 py-2.5 text-sm font-medium transition-colors';

  const thClass = 'text-left text-xs font-medium text-zinc-500 uppercase tracking-wider px-4 py-3';
  const tdClass = 'px-4 py-3.5 text-sm text-zinc-300 whitespace-nowrap';

  // --------------- Render helpers ---------------
  const renderLoading = () => (
    <div className="space-y-2 py-6">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="h-10 animate-pulse rounded-lg bg-zinc-800" />
      ))}
    </div>
  );

  const renderEmpty = (label: string) => (
    <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
      <Ban className="mb-3 h-10 w-10 text-zinc-700" />
      <p className="text-sm font-medium text-zinc-500">
        No {label} restrictions configured
      </p>
      <p className="mt-1 text-xs text-zinc-600">
        Add entries to start enforcing access controls.
      </p>
    </div>
  );

  const formatDate = (d: string) => {
    try {
      return new Date(d).toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
    } catch {
      return d;
    }
  };

  // --------------- IP Tab ---------------
  const renderIpTab = () => (
    <>
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">IP Address Rules</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Block individual IPs or CIDR ranges from accessing protected services
          </p>
        </div>
        <button
          className={showIpForm ? secondaryBtn : primaryBtn}
          onClick={() => setShowIpForm((v) => !v)}
        >
          {showIpForm ? (
            <>
              <X className="h-3.5 w-3.5" />
              Cancel
            </>
          ) : (
            <>
              <Plus className="h-3.5 w-3.5" />
              Add Rule
            </>
          )}
        </button>
      </div>

      {showIpForm && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5 mb-5 space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Target IP Address
              </label>
              <input
                type="text"
                className={inputClass}
                placeholder="192.168.1.0/24 or 10.0.0.1"
                value={ipForm.ip}
                onChange={(e) => setIpForm({ ...ipForm, ip: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Block Reason
              </label>
              <input
                type="text"
                className={inputClass}
                placeholder="Brute force attack source"
                value={ipForm.reason}
                onChange={(e) => setIpForm({ ...ipForm, reason: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                TTL (seconds)
                <span className="ml-1 text-zinc-600 font-normal">optional</span>
              </label>
              <input
                type="number"
                className={inputClass}
                placeholder="3600 (1 hour)"
                value={ipForm.ttl}
                onChange={(e) => setIpForm({ ...ipForm, ttl: e.target.value })}
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button className={primaryBtn} onClick={addIp}>
              <Save className="h-3.5 w-3.5" />
              Save Rule
            </button>
          </div>
        </div>
      )}

      {ipLoading ? (
        renderLoading()
      ) : ips.length === 0 ? (
        renderEmpty('IP')
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Target IP</th>
                <th className={thClass}>Reason</th>
                <th className={thClass}>Source</th>
                <th className={thClass}>Created</th>
                <th className={thClass}>Expires</th>
                <th className={thClass}>Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {ips.map((entry) => (
                <tr key={entry.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className={tdClass}>
                    <span className="font-mono text-zinc-200">{entry.ip}</span>
                    {entry.cidr && (
                      <span className="ml-1 text-zinc-500">/{entry.cidr}</span>
                    )}
                  </td>
                  <td className={tdClass}>
                    {entry.reason || <span className="text-zinc-600">--</span>}
                  </td>
                  <td className={tdClass}>
                    <span className="inline-block bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-md px-2 py-0.5 text-xs font-medium">
                      {entry.source}
                    </span>
                  </td>
                  <td className={tdClass}>
                    <span className="tabular-nums">{formatDate(entry.created_at)}</span>
                  </td>
                  <td className={tdClass}>
                    {entry.expires_at ? (
                      <span className="tabular-nums">{formatDate(entry.expires_at)}</span>
                    ) : (
                      <span className="text-zinc-600 text-xs">Permanent</span>
                    )}
                  </td>
                  <td className={tdClass}>
                    <button className={dangerBtn} onClick={() => deleteIp(entry.id)}>
                      <Trash2 className="h-3 w-3" />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );

  // --------------- ASN Tab ---------------
  const renderAsnTab = () => (
    <>
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Network Rules (ASN)</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Block entire autonomous systems by ASN number
          </p>
        </div>
        <button
          className={showAsnForm ? secondaryBtn : primaryBtn}
          onClick={() => setShowAsnForm((v) => !v)}
        >
          {showAsnForm ? (
            <>
              <X className="h-3.5 w-3.5" />
              Cancel
            </>
          ) : (
            <>
              <Plus className="h-3.5 w-3.5" />
              Add Rule
            </>
          )}
        </button>
      </div>

      {showAsnForm && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5 mb-5 space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                ASN Number
              </label>
              <input
                type="number"
                className={inputClass}
                placeholder="13335"
                value={asnForm.asn}
                onChange={(e) => setAsnForm({ ...asnForm, asn: e.target.value })}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Block Reason
              </label>
              <input
                type="text"
                className={inputClass}
                placeholder="Known malicious traffic origin"
                value={asnForm.reason}
                onChange={(e) => setAsnForm({ ...asnForm, reason: e.target.value })}
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button className={primaryBtn} onClick={addAsn}>
              <Save className="h-3.5 w-3.5" />
              Save Rule
            </button>
          </div>
        </div>
      )}

      {asnLoading ? (
        renderLoading()
      ) : asns.length === 0 ? (
        renderEmpty('ASN')
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>ASN</th>
                <th className={thClass}>Network Name</th>
                <th className={thClass}>Action</th>
                <th className={thClass}>Reason</th>
                <th className={thClass}>Created</th>
                <th className={thClass}>Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {asns.map((entry) => (
                <tr key={entry.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className={tdClass}>
                    <span className="font-mono font-medium text-zinc-200">AS{entry.asn}</span>
                  </td>
                  <td className={tdClass}>
                    {entry.name ?? <span className="text-zinc-600">--</span>}
                  </td>
                  <td className={tdClass}>
                    <span className="inline-block bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-md px-2 py-0.5 text-xs font-medium uppercase">
                      {entry.action}
                    </span>
                  </td>
                  <td className={tdClass}>
                    {entry.reason ?? <span className="text-zinc-600">--</span>}
                  </td>
                  <td className={tdClass}>
                    <span className="tabular-nums">{formatDate(entry.created_at)}</span>
                  </td>
                  <td className={tdClass}>
                    <button className={dangerBtn} onClick={() => deleteAsn(entry.id)}>
                      <Trash2 className="h-3 w-3" />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );

  // --------------- Country Tab ---------------
  const renderCountryTab = () => (
    <>
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">Geographic Restriction Rules</h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            Enforce country-level access controls using ISO 3166-1 alpha-2 codes
          </p>
        </div>
        <button
          className={showCountryForm ? secondaryBtn : primaryBtn}
          onClick={() => setShowCountryForm((v) => !v)}
        >
          {showCountryForm ? (
            <>
              <X className="h-3.5 w-3.5" />
              Cancel
            </>
          ) : (
            <>
              <Plus className="h-3.5 w-3.5" />
              Add Rule
            </>
          )}
        </button>
      </div>

      {showCountryForm && (
        <div className="rounded-xl border border-zinc-700 bg-zinc-900/50 p-5 mb-5 space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Country Code (ISO 3166-1)
              </label>
              <input
                type="text"
                className={inputClass}
                placeholder="CN, RU, IR, etc."
                maxLength={2}
                value={countryForm.code}
                onChange={(e) =>
                  setCountryForm({ ...countryForm, code: e.target.value.toUpperCase() })
                }
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                Block Reason
              </label>
              <input
                type="text"
                className={inputClass}
                placeholder="High volume attack traffic origin"
                value={countryForm.reason}
                onChange={(e) => setCountryForm({ ...countryForm, reason: e.target.value })}
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button className={primaryBtn} onClick={addCountry}>
              <Save className="h-3.5 w-3.5" />
              Save Rule
            </button>
          </div>
        </div>
      )}

      {countryLoading ? (
        renderLoading()
      ) : countries.length === 0 ? (
        renderEmpty('geographic')
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Code</th>
                <th className={thClass}>Country</th>
                <th className={thClass}>Action</th>
                <th className={thClass}>Reason</th>
                <th className={thClass}>Created</th>
                <th className={thClass}>Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {countries.map((entry) => (
                <tr key={entry.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className={tdClass}>
                    <span className="font-mono font-bold text-zinc-200">
                      <CountryFlag code={entry.country_code} size={16} className="mr-1 align-middle" /> {entry.country_code}
                    </span>
                  </td>
                  <td className={tdClass}>
                    {entry.country_name ?? <span className="text-zinc-600">--</span>}
                  </td>
                  <td className={tdClass}>
                    <span className="inline-block bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-md px-2 py-0.5 text-xs font-medium uppercase">
                      {entry.action}
                    </span>
                  </td>
                  <td className={tdClass}>
                    {entry.reason ?? <span className="text-zinc-600">--</span>}
                  </td>
                  <td className={tdClass}>
                    <span className="tabular-nums">{formatDate(entry.created_at)}</span>
                  </td>
                  <td className={tdClass}>
                    <button className={dangerBtn} onClick={() => deleteCountry(entry.id)}>
                      <Trash2 className="h-3 w-3" />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );

  // --------------- Tab config ---------------
  const tabConfig: { key: Tab; label: string; icon: React.ReactNode; count: number }[] = [
    {
      key: 'ip',
      label: 'IP Blocklist',
      icon: <Hash className="h-3.5 w-3.5" />,
      count: ips.length,
    },
    {
      key: 'asn',
      label: 'Network Blocklist (ASN)',
      icon: <Network className="h-3.5 w-3.5" />,
      count: asns.length,
    },
    {
      key: 'country',
      label: 'Geographic Restrictions',
      icon: <Globe className="h-3.5 w-3.5" />,
      count: countries.length,
    },
  ];

  // --------------- Main render ---------------
  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-orange-400" />
          <h1 className="text-2xl font-bold text-zinc-100">Blocklist Engine</h1>
        </div>
        <p className="mt-1 text-sm text-zinc-500 ml-9">
          IP, ASN, and geographic access control
        </p>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-3 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
        <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
        <p className="text-xs text-zinc-500 leading-relaxed">
          Rules take effect immediately across all edge nodes. IP and CIDR blocks support optional
          TTL for automatic expiration. ASN and country restrictions are permanent until manually removed.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {tabConfig.map((tab) => (
          <button
            key={tab.key}
            className={tabClass(tab.key)}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.icon}
            {tab.label}
            {tab.count > 0 && (
              <span className="ml-1 rounded-full bg-zinc-700 px-2 py-0.5 text-xs font-medium tabular-nums text-zinc-300">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
        {activeTab === 'ip' && renderIpTab()}
        {activeTab === 'asn' && renderAsnTab()}
        {activeTab === 'country' && renderCountryTab()}
      </div>
    </div>
  );
}
