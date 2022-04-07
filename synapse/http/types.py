from typing import Iterable, Mapping, Union

# the type of the query params, to be passed into `urlencode` with `doseq=True`.
QueryParamValue = Union[str, bytes, Iterable[Union[str, bytes]]]
QueryParams = Union[Mapping[str, QueryParamValue], Mapping[bytes, QueryParamValue]]

__all__ = ["QueryParams"]
