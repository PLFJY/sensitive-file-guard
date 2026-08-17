// MCH8 harmless content script: a benign DOM annotation, no data collection.
const mark = document.createElement("meta");
mark.setAttribute("name", "mch8-fixture");
mark.setAttribute("content", "harmless-dom-annotation");
document.head?.appendChild(mark);
