let token = sessionStorage.getItem('adminToken') || '';
const q = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const response = await fetch(`/api/v1/admin/${path}`, {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const value = await response.json().catch(() => ({}));
    throw Error(value.error?.message || String(response.status));
  }
  return response.status === 204 ? null : response.json();
}

function cell(value) {
  const element = document.createElement('td');
  element.textContent = String(value ?? '');
  return element;
}

function actionButton(label, action) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.addEventListener('click', () => {
    Promise.resolve(action()).catch(showError);
  });
  return button;
}

function actionCell(label, action) {
  const element = document.createElement('td');
  element.append(actionButton(label, action));
  return element;
}

function replaceRows(selector, rows) {
  const target = q(selector);
  target.replaceChildren(...rows);
}

function showError(value) {
  q('#msg').textContent = value instanceof Error ? value.message : String(value);
}

function formatActionResult(result) {
  const research = result?.trafficResearch;
  if (!research) return result ? JSON.stringify(result) : '';
  const coverage = research.observedConnectionCount > 0
    ? Math.round(research.identifiedProcessConnectionCount * 100 / research.observedConnectionCount)
    : 0;
  const exitVerdict = {
    MATCHED: '一致', MISMATCHED: '不一致 ⚠️', INCONCLUSIVE: '无法判断',
  }[research.exitIdentityConsistency] || research.exitIdentityConsistency;
  const bypassVerdict = {
    BLOCKED: '已阻断', REACHABLE: '可绕过 ⚠️', INCONCLUSIVE: '无法判断',
  }[research.physicalBypassProbe] || research.physicalBypassProbe;
  const endpoints = research.entries.map((entry) =>
    `${entry.service}/${entry.client} ${entry.host} ${entry.network}:${entry.port} ` +
    `${entry.route} ×${entry.connections} ↑${entry.upBytes} ↓${entry.downBytes}`);
  return [
    `出口一致性：${exitVerdict} · 物理网卡绕过：${bypassVerdict}`,
    `连接：${research.observedConnectionCount}（代理 ${research.proxiedConnectionCount} / ` +
      `直连 ${research.directConnectionCount} / 阻断 ${research.blockedConnectionCount}）`,
    `进程识别覆盖率：${coverage}% · 未受控 DIRECT 日志：${research.directRouteAttemptCount} · ` +
      `受控直连：${research.managedDirectRouteCount}`,
    `精确视频网页直连：${research.webManagedDirectConnectionCount ?? 0}`,
    `微信试验：识别 ${research.weChatConnectionCount}（直连 ${research.weChatManagedDirectConnectionCount} / ` +
      `代理 ${research.weChatProxiedConnectionCount} / 阻断 ${research.weChatBlockedConnectionCount}） · ` +
      `微信 endpoint 未识别进程 ${research.weChatEndpointUnknownProcessConnectionCount}`,
    `隔离违规：Claude DIRECT ${research.protectedDirectConnectionCount} / ` +
      `未知进程受控直连 ${research.unknownManagedDirectConnectionCount} / ` +
      `其他进程受控直连 ${research.otherManagedDirectConnectionCount}`,
    `保护：Kill Switch ${research.killSwitchArmed ? '是' : '否'} / ` +
      `TUN ${research.tunPresent ? '是' : '否'} / DNS ${research.protectedDNSConfigured ? '是' : '否'} / ` +
      `异常观测 ${research.unsafeProtectionObservationCount}`,
    ...endpoints,
    research.droppedEndpointCount > 0 ? `另有 ${research.droppedEndpointCount} 组未显示` : '',
  ].filter(Boolean).join('\n');
}

async function load() {
  const [users, devices, catalog, trafficPolicy, actions] = await Promise.all([
    api('users'),
    api('devices'),
    api('exit-catalog'),
    api('traffic-policy'),
    api('device-actions'),
  ]);
  const catalogMeta = q('#catalog-meta');
  catalogMeta.dataset.revision = String(catalog.revision);
  catalogMeta.textContent = catalog.revision > 0
    ? `当前版本 ${catalog.revision} · 更新时间 ${new Date(catalog.updatedAt * 1_000).toLocaleString()}`
    : '尚未上传云端节点目录';
  const trafficPolicyMeta = q('#traffic-policy-meta');
  trafficPolicyMeta.dataset.revision = String(trafficPolicy.revision);
  trafficPolicyMeta.textContent = trafficPolicy.revision > 0
    ? `当前版本 ${trafficPolicy.revision} · 更新时间 ${new Date(trafficPolicy.updatedAt * 1_000).toLocaleString()}`
    : '尚未启用国内精确直连';
  q('#traffic-policy-json').value = JSON.stringify(
    JSON.parse(trafficPolicy.json), null, 2,
  );
  replaceRows('#users', users.users.map((user) => {
    const row = document.createElement('tr');
    row.append(
      cell(user.email),
      cell(user.status),
      cell(`${user.usageBytes} / ${user.quotaBytes ?? '∞'}`),
      actionCell(user.status === 'active' ? '停用' : '启用', async () => {
        await api(`users/${encodeURIComponent(user.id)}`, {
          method: 'PATCH',
          body: JSON.stringify({ status: user.status === 'active' ? 'disabled' : 'active' }),
        });
        await load();
      }),
    );
    return row;
  }));
  replaceRows('#devices', devices.devices.map((device) => {
    const row = document.createElement('tr');
    row.append(
      cell(device.email),
      cell(device.name),
      cell(device.status),
      cell(device.tailscaleNodeId),
      (() => {
        const element = document.createElement('td');
        const enqueue = (label, action, confirmFirst = false) => element.append(actionButton(label, async () => {
          if (confirmFirst && !confirm('仅当此设备已处于 Protected Offline 时重试保护？健康连接不会被断开。')) return;
          await api('device-actions', { method: 'POST', body: JSON.stringify({ deviceId: device.id, action }) });
          await load();
        }));
        if (device.status !== 'revoked') {
          enqueue('诊断快照', 'diagnostic_snapshot');
          enqueue('Claude/微信流量', 'claude_traffic_snapshot');
          enqueue('刷新目录', 'refresh_catalog');
          enqueue('重试保护', 'retry_protection', true);
        }
        element.append(actionButton('撤销', async () => {
        if (!confirm('撤销此设备并从 tailnet 删除？')) return;
        await api(`devices/${encodeURIComponent(device.id)}`, { method: 'DELETE' });
        await load();
        }));
        return element;
      })(),
    );
    return row;
  }));
  replaceRows('#device-actions', actions.actions.map((action) => {
    const row = document.createElement('tr');
    const resultCell = cell(formatActionResult(action.result));
    resultCell.className = 'action-result';
    row.append(
      cell(new Date(action.createdAt * 1_000).toLocaleString()),
      cell(action.deviceId), cell(action.action), cell(action.status),
      resultCell,
    );
    return row;
  }));
}

async function save() {
  token = q('#token').value;
  sessionStorage.setItem('adminToken', token);
  try {
    await load();
    q('#login').hidden = true;
    q('#app').hidden = false;
    q('#msg').textContent = '';
  } catch (error) {
    showError(error);
  }
}

q('#login-button').addEventListener('click', save);
q('#catalog-file').addEventListener('change', async (event) => {
  try {
    const [file] = event.target.files;
    if (!file) return;
    if (file.size < 11 || file.size > 1024 * 1024) {
      throw Error('目录文件必须为 11 bytes–1 MiB');
    }
    q('#catalog-yaml').value = await file.text();
    q('#msg').textContent = '目录已在本机载入；确认内容后再替换云端版本。';
  } catch (error) {
    event.target.value = '';
    showError(error);
  }
});
q('#catalog-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const yaml = q('#catalog-yaml').value;
    const expectedRevision = Number(q('#catalog-meta').dataset.revision || '0');
    const value = await api('exit-catalog', {
      method: 'PUT',
      body: JSON.stringify({ yaml, expectedRevision }),
    });
    q('#catalog-yaml').value = '';
    q('#msg').textContent = `节点目录已更新到版本 ${value.revision}`;
    await load();
  } catch (error) {
    showError(error);
  }
});

async function replaceTrafficPolicy(policy) {
  const expectedRevision = Number(q('#traffic-policy-meta').dataset.revision || '0');
  const value = await api('traffic-policy', {
    method: 'PUT',
    body: JSON.stringify({ policy, expectedRevision }),
  });
  q('#msg').textContent = `精确直连试验策略已更新到版本 ${value.revision}`;
  await load();
}

q('#traffic-policy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await replaceTrafficPolicy(JSON.parse(q('#traffic-policy-json').value));
  } catch (error) {
    showError(error);
  }
});

q('#clear-traffic-policy').addEventListener('click', async () => {
  if (!confirm('立即停止所有国内精确直连并让客户端安全重连？')) return;
  try {
    await replaceTrafficPolicy({ version: 1, domains: [], mediaEndpoints: [] });
  } catch (error) {
    showError(error);
  }
});

q('#clear-web-traffic-policy').addEventListener('click', async () => {
  if (!confirm('只停止 B站、腾讯视频、爱奇艺和优酷网页直连，保留原生微信试验？')) return;
  try {
    const current = JSON.parse(q('#traffic-policy-json').value);
    await replaceTrafficPolicy({
      version: 2,
      domains: current.domains || [],
      mediaEndpoints: current.mediaEndpoints || [],
      webDomains: [],
    });
  } catch (error) {
    showError(error);
  }
});

if (token) {
  q('#token').value = token;
  save();
}
