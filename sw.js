self.addEventListener("push", event => {
  const data = event.data
    ? event.data.json()
    : {};

  const title =
    data.title || "StyleSpot";

  const message =
    data.message || "You have a new notification.";

  event.waitUntil(
    self.registration.showNotification(
      title,
      {
        body: message,
        icon: "/icon-192.png",
        badge: "/icon-192.png",
        data: {
          bookingId:
            data.bookingId || null
        }
      }
    )
  );
});

self.addEventListener(
  "notificationclick",
  event => {

    event.notification.close();

    event.waitUntil(
      clients.matchAll({
        type: "window",
        includeUncontrolled: true
      }).then(
        clientList => {

          for (
            const client of clientList
          ) {
            if (
              "focus" in client
            ) {
              return client.focus();
            }
          }

          if (
            clients.openWindow
          ) {
            return clients.openWindow(
              "/barber.html"
            );
          }

        }
      )
    );

  }
);
