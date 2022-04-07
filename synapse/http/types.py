from typing import Dict, Iterable, List, Mapping, Union

# the type of the query params, to be passed into `urlencode`
QueryParamValue = Union[str, bytes, Iterable[Union[str, bytes]]]
QueryParams = Union[Mapping[str, QueryParamValue], Mapping[bytes, QueryParamValue]]

QueryArgs = Dict[str, Union[str, List[str]]]
