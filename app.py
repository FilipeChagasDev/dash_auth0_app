# ATTENTION: If the environment variables are in a path different from ./.env,
# uncomment and load them before importing the auth0 package
#from dotenv import load_dotenv
#load_dotenv()

from dash import Dash, html, dcc, Input, Output
from auth0 import Auth0Auth, get_user_info


app = Dash(__name__, suppress_callback_exceptions=True)
auth = Auth0Auth(app)


app.layout = lambda: html.Div(
    children=[
        html.H2("Demo Dash + Auth0"),
        html.A("Logout", href="/logout", style={"fontWeight": "bold"}),
        html.H3("Profile Data:"),
        html.Pre(html.Code(str(get_user_info()))),
        html.Button("Say Hello", id="hello-btn"),
        html.Div(id="hello-output"),
        dcc.Location(id="url-dummy"),
    ],
)


@app.callback(
    Output("hello-output", "children"),
    Input("hello-btn", "n_clicks"),
    prevent_initial_call=True
)
def say_hello(n_clicks):
    user = get_user_info()
    first_name = user.get("given_name", "")
    last_name = user.get("family_name", "")
    return f"Hello, {first_name} {last_name}"


if __name__ == "__main__":
    app.run_server(debug=True, host="127.0.0.1", port=8050)
