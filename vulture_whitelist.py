"""Public caller surface that a source-only reachability scan cannot observe."""

from c2patxt.signing import ModelType, Signer
from c2patxt.status import StatusCode
from c2patxt.verdict import Verdict

_PUBLIC_CALLER_SURFACE = (
    ModelType.GENERIC,
    ModelType.HUGGINGFACE_TRANSFORMERS,
    ModelType.ONNX,
    ModelType.PYTORCH,
    ModelType.TENSORFLOW,
    Signer.leaf,
    Verdict.raise_for_state,
    StatusCode.__doc__,
)
