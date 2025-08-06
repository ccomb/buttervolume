from bottle import Bottle, response

# The Bottle application for the cluster API
cluster_api_app = Bottle()


@cluster_api_app.get("/status")
def status():
    """A simple status endpoint to check if the API server is running."""
    response.content_type = "application/json"
    return '{"status": "ok"}'
