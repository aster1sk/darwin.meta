module.exports = {
    "publicPath": "/app",
    "transpileDependencies": [
        "vuetify"
    ],
    devServer: {
        proxy: 'https://paranoid.computer/',
    }
}
