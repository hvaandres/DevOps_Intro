"""
Azure API Platform — Function App Entry Point
Python v2 programming model with Blueprint-based route organization.
"""
import azure.functions as func

from blueprints.blob_data import bp as blob_data_bp
from blueprints.cosmos_data import bp as cosmos_data_bp
from blueprints.health import bp as health_bp
from blueprints.sql_data import bp as sql_data_bp

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Register all blueprints
app.register_functions(health_bp)
app.register_functions(blob_data_bp)
app.register_functions(sql_data_bp)
app.register_functions(cosmos_data_bp)
