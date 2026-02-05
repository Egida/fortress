
async function fortressRequest<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Fortress API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fortressGet<T = unknown>(path: string): Promise<T> {
  return fortressRequest<T>(path);
}

export async function fortressPost<T = unknown>(path: string, body?: unknown): Promise<T> {
  return fortressRequest<T>(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function fortressPut<T = unknown>(path: string, body?: unknown): Promise<T> {
  return fortressRequest<T>(path, {
    method: 'PUT',
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function fortressDelete<T = unknown>(path: string): Promise<T> {
  return fortressRequest<T>(path, { method: 'DELETE' });
}

export async function fetchApi<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  return fortressRequest<T>(path, options);
}
