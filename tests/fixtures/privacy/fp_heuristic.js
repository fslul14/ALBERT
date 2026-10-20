function probe(){var c=document.createElement("canvas");var d=c.toDataURL();var g=c.getContext("webgl");
var e=g.getExtension("WEBGL_debug_renderer_info");var a=new OfflineAudioContext(1,44100,44100);return [d,e,a];}
