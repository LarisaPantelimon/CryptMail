function getCsrfToken(cookieName = 'csrf_access_token') {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith(`${cookieName}=`))
    ?.split('=')[1] || '';
}

async function apiFetch(url, options = {}) {
  // Asigura-te ca URL-ul este relativ ?i începe cu /api
  const fullUrl = url.startsWith('/api') ? url : `/api${url.startsWith('/') ? url : `/${url}`}`;
  const isPost = (options.method || 'GET').toUpperCase() === 'POST';
  const csrfCookieName = url.endsWith('/refresh') ? 'csrf_refresh_token' : 'csrf_access_token';
  const csrfToken = getCsrfToken(csrfCookieName);

  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };
  if (isPost && csrfToken) {
    headers['X-CSRF-TOKEN'] = csrfToken;
  }

  //console.log('Fetching from:', fullUrl); // Adauga log pentru depanare
  const response = await fetch(fullUrl, {
    ...options,
    headers,
    credentials: 'include',
  });

  // Skip refresh logic for /check-auth, /refresh, /login, /logout
  if (
    response.status === 401 &&
    !options._retry &&
    !fullUrl.endsWith('/api/check-auth') &&
    !fullUrl.endsWith('/api/refresh') &&
    !fullUrl.endsWith('/api/login') &&
    !fullUrl.endsWith('/api/logout')
  ) {
    try {
      const csrfToken = document.cookie
        .split('; ')
        .find(row => row.startsWith('csrf_access_token='))
        ?.split('=')[1];
      const refreshResponse = await fetch('/api/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': csrfToken,
        },
      });

      if (!refreshResponse.ok) {
        throw new Error('Refresh token failed');
      }

      // Retry original request
      return apiFetch(url, { ...options, _retry: true });
    } catch (error) {
      if (options.onAuthFailure) {
        options.onAuthFailure();
      }
      if (!fullUrl.endsWith('/api/login')) {
        window.location.href = '/Login';
      }
      throw error;
    }
  }

  return response;
}

export default apiFetch;