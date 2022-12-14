from typing import Dict, List, Optional

class MatrixResponse:
    code: int
    phrase: str
    content: bytes
    headers: Dict[str, str]

class HttpClient:
    async def request(
        self,
        url: str,
        method: str,
        headers: Dict[bytes, List[bytes]],
        body: Optional[bytes],
    ) -> MatrixResponse: ...
