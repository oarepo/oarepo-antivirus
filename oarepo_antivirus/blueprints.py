from flask import Blueprint

blueprint = Blueprint(
    "oarepo_antivirus",
    __name__,
    template_folder="templates",
)