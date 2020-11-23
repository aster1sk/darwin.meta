<template>
  <v-app>
    <v-app-bar app color="#1d2e43" dark>
      <v-toolbar-title>darwin.meta</v-toolbar-title>

      <v-spacer></v-spacer>

      <v-btn href="/app/" text>
        <v-icon>mdi-account</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <Dashboard />
    </v-main>
  </v-app>
</template>

<script>
import Dashboard from "./components/Dashboard";

export default {
  name: "App",

  components: {
    Dashboard,
  },

  data: () => ({
    //
  }),
};
</script>
