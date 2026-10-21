// Sentinel AI Service Worker for Standards-Based Web Push Notifications
// Handles background push events and navigation when notification is tapped

self.addEventListener('push', (event) => {
  let data = {};
  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data = {
        title: 'Sentinel AI Authorization',
        body: event.data.text(),
      };
    }
  }

  const title = data.title || 'Sentinel AI Biometric Authorization';
  const options = {
    body: data.body || 'A pending sign-in request requires your biometric authorization.',
    icon: data.icon || '/icons/icon-192x192.png',
    badge: '/icons/badge-72x72.png',
    vibrate: [100, 50, 100],
    data: data.data || {},
    requireInteraction: true,
    actions: [
      { action: 'authorize', title: 'Authorize Now' },
      { action: 'cancel', title: 'Dismiss' },
    ],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'cancel') {
    return;
  }

  const targetUrl = event.notification.data?.url || '/verify-mobile';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if (client.url.includes('/verify-mobile') && 'focus' in client) {
          if (targetUrl) {
            client.navigate(targetUrl);
          }
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
