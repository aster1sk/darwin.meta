<template>
  <v-container fluid>
    <v-row>
      <v-col>
        <h3>Hello {{ user.username }}!</h3>
        <p>Put this in ~/.bin/share:</p>

        <pre>
#!/bin/bash

FILE=$1
TITLE=$2
DESCRIPTION=$3
TOKEN={{ user.token }}

curl -sSL \
  -F "title=${TITLE}" \
  -F "description=${DESCRIPTION}" \
  -F "file=@${FILE}" \
  -H "Authorization: Bearer $TOKEN" \
  https://acablabs.com/u/

# Usage: share "path/to/file.jpg" "*optional* title of post" "*optional* description of post"
# Be sure to `chmod a+x ~/.bin/share`
# as well ensure ~/.bin is in your $PATH
  </pre
        >
      </v-col>
    </v-row>

    <v-row dense>
      <v-col v-for="(event, idx) in events" :key="idx">
        <v-card class="mx-auto" max-width="400">
          <v-img
            class="white--text align-end"
            height="200px"
            :src="event.image"
          >
            <v-card-title>{{ event.title }}</v-card-title>
          </v-img>

          <v-card-subtitle class="pb-0">
          Posted by <strong>{{ event.user }}
          </v-card-subtitle>

          <v-card-text class="text--primary">
            <small><strong>on</strong> {{ event.timestamp }}</small>
            <br />
            <small><strong>mime</strong> {{ event.content_type }}</small>
            <div v-if="event.description.length < 50">
              {{ event.description }}
            </div>
            <div v-else>{{ event.description.substring(0, 50) + ".." }}</div>
          </v-card-text>

          <v-divider class="mx-4"></v-divider>

          <v-card-actions>
            <v-btn color="green" text :href="event.url_string" target="_blank">
              Original URL
            </v-btn>
            <v-btn color="green" text :href="event.image" target="_blank">
              View Image
            </v-btn>
          </v-card-actions>

        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
export default {
  name: "Dashboard",
  data() {
    return {
      user: {},
      events: [],

      eventHeaders: [
        { text: "Date", value: "timestamp" },
        { text: "Title", value: "title" },
        { text: "Description", value: "description" },
        { text: "User", value: "user" },
        { text: "Channel", value: "channel" },
        { text: "Content Type", value: "content_type" },
      ],
      ts: ["timestamp"],
      status: "disconnected",
    };
  },
  mounted() {
    this.getUser();
    this.getEvents();
    this.runWebsocket();
  },
  methods: {
    getEvents() {
      var self = this;
      function status(response) {
        if (response.status >= 200 && response.status < 300) {
          return Promise.resolve(response);
        } else {
          return Promise.reject(new Error(response.statusText));
        }
      }
      function json(response) {
        return response.json();
      }
      fetch("/api/v1/events")
        .then(status)
        .then(json)
        .then(function (data) {
          self.events = data;
        })
        .catch(function (error) {
          console.log("Request failed", error);
        });
    },
    getUser() {
      var self = this;
      function status(response) {
        if (response.status >= 200 && response.status < 300) {
          return Promise.resolve(response);
        } else {
          return Promise.reject(new Error(response.statusText));
        }
      }
      function json(response) {
        return response.json();
      }
      fetch("/api/v1/me")
        .then(status)
        .then(json)
        .then(function (data) {
          self.user = data;
        })
        .catch(function (error) {
          console.log("Request failed", error);
        });
    },

    runWebsocket() {
      var self = this;
      var loc = window.location,
        url;
      if (loc.protocol === "https:") {
        url = "wss:";
      } else {
        url = "ws:";
      }
      url += "//" + loc.host;
      url += "/ws";

      var c = new WebSocket(url);
      var send = function (data) {
        c.send(data);
      };
      c.onmessage = function (msg) {
        self.events.unshift(JSON.parse(msg.data));
      };
      c.onopen = function () {
        self.status = "connected";
        console.log("websocket connected");
        setInterval(function () {
          send("ping");
        }, 1000);
      };
    },
  },
};
</script>
