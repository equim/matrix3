// matrix³ dummy service worker for testing.
self.addEventListener('install', (event) => {
    console.log('SW: Install event');
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('SW: Activate event');
    event.waitUntil(clients.claim());
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Intercept the main HTML document request
    if (url.pathname === '/') {
        console.log('SW: Intercepting root navigation');
        event.respondWith(
            fetch(event.request).then(async (response) => {
                let text = await response.text();

                text = text.replace(
                    '<!-- SW_STATUS -->',
                    '<span style="color:red"><b>active</b></span>'
                );

                let newHeaders = new Headers(response.headers);

                return new Response(text, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: newHeaders
                });
            }).catch(err => {
                console.error("SW Fetch Error:", err);
                return new Response("SW Error: " + err);
            })
        );
        return;
    }

    event.respondWith(fetch(event.request));
});
