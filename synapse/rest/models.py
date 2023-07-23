from pydantic import BaseModel, ConfigDict


class RequestBodyModel(BaseModel):
    """A custom version of Pydantic's BaseModel which

     - ignores unknown fields and
     - does not allow fields to be overwritten after construction,

    but otherwise uses Pydantic's default behaviour.

    Ignoring unknown fields is a useful default. It means that clients can provide
    unstable field not known to the server without the request being refused outright.

    Subclassing in this way is recommended by
    https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally
    """

    model_config = ConfigDict(extra="ignore", frozen=True)
