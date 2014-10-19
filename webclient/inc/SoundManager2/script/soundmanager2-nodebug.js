/** @license
 *
 * SoundManager 2: JavaScript Sound for the Web
 * ----------------------------------------------
 * http://schillmania.com/projects/soundmanager2/
 *
 * Copyright (c) 2007, Scott Schiller. All rights reserved.
 * Code provided under the BSD License:
 * http://schillmania.com/projects/soundmanager2/license.txt
 *
 * V2.97a.20111220
 */

/*global window, SM2_DEFER, sm2Debugger, console, document, navigator, setTimeout, setInterval, clearInterval, Audio */
/* jslint regexp: true, sloppy: true, white: true, nomen: true, plusplus: true */

(function(window) {
var soundManager = null;
function SoundManager(smURL, smID) {
  this.flashVersion = 8;
  this.debugMode = false;
  this.debugFlash = false;
  this.useConsole = true;
  this.consoleOnly = true;
  this.waitForWindowLoad = false;
  this.bgColor = '#ffffff';
  this.useHighPerformance = false;
  this.flashPollingInterval = null;
  this.html5PollingInterval = null;
  this.flashLoadTimeout = 1000;
  this.wmode = null;
  this.allowScriptAccess = 'always';
  this.useFlashBlock = false;
  this.useHTML5Audio = true;
  this.html5Test = /^(probably|maybe)$/i;
  this.preferFlash = true;
  this.noSWFCache = false;
  this.audioFormats = {
    'mp3': {
      'type': ['audio/mpeg; codecs="mp3"', 'audio/mpeg', 'audio/mp3', 'audio/MPA', 'audio/mpa-robust'],
      'required': true
    },
    'mp4': {
      'related': ['aac','m4a'],
      'type': ['audio/mp4; codecs="mp4a.40.2"', 'audio/aac', 'audio/x-m4a', 'audio/MP4A-LATM', 'audio/mpeg4-generic'],
      'required': false
    },
    'ogg': {
      'type': ['audio/ogg; codecs=vorbis'],
      'required': false
    },
    'wav': {
      'type': ['audio/wav; codecs="1"', 'audio/wav', 'audio/wave', 'audio/x-wav'],
      'required': false
    }
  };
  this.defaultOptions = {
    'autoLoad': false,
    'autoPlay': false,
    'from': null,
    'loops': 1,
    'onid3': null,
    'onload': null,
    'whileloading': null,
    'onplay': null,
    'onpause': null,
    'onresume': null,
    'whileplaying': null,
    'onposition': null,
    'onstop': null,
    'onfailure': null,
    'onfinish': null,
    'multiShot': true,
    'multiShotEvents': false,
    'position': null,
    'pan': 0,
    'stream': true,
    'to': null,
    'type': null,
    'usePolicyFile': false,
    'volume': 100
  };
  this.flash9Options = {
    'isMovieStar': null,
    'usePeakData': false,
    'useWaveformData': false,
    'useEQData': false,
    'onbufferchange': null,
    'ondataerror': null
  };
  this.movieStarOptions = {
    'bufferTime': 3,
    'serverURL': null,
    'onconnect': null,
    'duration': null
  };
  this.movieID = 'sm2-container';
  this.id = (smID || 'sm2movie');
  this.debugID = 'soundmanager-debug';
  this.debugURLParam = /([#?&])debug=1/i;
  this.versionNumber = 'V2.97a.20111220';
  this.version = null;
  this.movieURL = null;
  this.url = (smURL || null);
  this.altURL = null;
  this.swfLoaded = false;
  this.enabled = false;
  this.oMC = null;
  this.sounds = {};
  this.soundIDs = [];
  this.muted = false;
  this.didFlashBlock = false;
  this.filePattern = null;
  this.filePatterns = {
    'flash8': /\.mp3(\?.*)?$/i,
    'flash9': /\.mp3(\?.*)?$/i
  };
  this.features = {
    'buffering': false,
    'peakData': false,
    'waveformData': false,
    'eqData': false,
    'movieStar': false
  };
  this.sandbox = {
  };
  this.hasHTML5 = (function() {
    try {
      return (typeof Audio !== 'undefined' && typeof new Audio().canPlayType !== 'undefined');
    } catch(e) {
      return false;
    }
  }());
  this.html5 = {
    'usingFlash': null
  };
  this.flash = {};
  this.html5Only = false;
  this.ignoreFlash = false;
  var SMSound,
  _s = this, _flash = null, _sm = 'soundManager', _smc = _sm+'::', _h5 = 'HTML5::', _id, _ua = navigator.userAgent, _win = window, _wl = _win.location.href.toString(), _doc = document, _doNothing, _init, _fV, _on_queue = [], _debugOpen = true, _debugTS, _didAppend = false, _appendSuccess = false, _didInit = false, _disabled = false, _windowLoaded = false, _wDS, _wdCount = 0, _initComplete, _mixin, _addOnEvent, _processOnEvents, _initUserOnload, _delayWaitForEI, _waitForEI, _setVersionInfo, _handleFocus, _strings, _initMovie, _domContentLoaded, _winOnLoad, _didDCLoaded, _getDocument, _createMovie, _catchError, _setPolling, _initDebug, _debugLevels = ['log', 'info', 'warn', 'error'], _defaultFlashVersion = 8, _disableObject, _failSafely, _normalizeMovieURL, _oRemoved = null, _oRemovedHTML = null, _str, _flashBlockHandler, _getSWFCSS, _swfCSS, _toggleDebug, _loopFix, _policyFix, _complain, _idCheck, _waitingForEI = false, _initPending = false, _smTimer, _onTimer, _startTimer, _stopTimer, _timerExecute, _h5TimerCount = 0, _h5IntervalTimer = null, _parseURL,
  _needsFlash = null, _featureCheck, _html5OK, _html5CanPlay, _html5Ext, _html5Unload, _domContentLoadedIE, _testHTML5, _event, _slice = Array.prototype.slice, _useGlobalHTML5Audio = false, _hasFlash, _detectFlash, _badSafariFix, _html5_events, _showSupport,
  _is_iDevice = _ua.match(/(ipad|iphone|ipod)/i), _is_firefox = _ua.match(/firefox/i), _is_android = _ua.match(/droid/i), _isIE = _ua.match(/msie/i), _isWebkit = _ua.match(/webkit/i), _isSafari = (_ua.match(/safari/i) && !_ua.match(/chrome/i)), _isOpera = (_ua.match(/opera/i)),
  _likesHTML5 = (_ua.match(/(mobile|pre\/|xoom)/i) || _is_iDevice),
  _isBadSafari = (!_wl.match(/usehtml5audio/i) && !_wl.match(/sm2\-ignorebadua/i) && _isSafari && !_ua.match(/silk/i) && _ua.match(/OS X 10_6_([3-7])/i)),
  _hasConsole = (typeof console !== 'undefined' && typeof console.log !== 'undefined'), _isFocused = (typeof _doc.hasFocus !== 'undefined'?_doc.hasFocus():null), _tryInitOnFocus = (_isSafari && typeof _doc.hasFocus === 'undefined'), _okToDisable = !_tryInitOnFocus, _flashMIME = /(mp3|mp4|mpa)/i,
  _emptyURL = 'about:blank',
  _overHTTP = (_doc.location?_doc.location.protocol.match(/http/i):null),
  _http = (!_overHTTP ? 'http:/'+'/' : ''),
  _netStreamMimeTypes = /^\s*audio\/(?:x-)?(?:mpeg4|aac|flv|mov|mp4||m4v|m4a|mp4v|3gp|3g2)\s*(?:$|;)/i,
  _netStreamTypes = ['mpeg4', 'aac', 'flv', 'mov', 'mp4', 'm4v', 'f4v', 'm4a', 'mp4v', '3gp', '3g2'],
  _netStreamPattern = new RegExp('\\.(' + _netStreamTypes.join('|') + ')(\\?.*)?$', 'i');
  this.mimePattern = /^\s*audio\/(?:x-)?(?:mp(?:eg|3))\s*(?:$|;)/i;
  this.useAltURL = !_overHTTP;
  this._global_a = null;
  _swfCSS = {
    'swfBox': 'sm2-object-box',
    'swfDefault': 'movieContainer',
    'swfError': 'swf_error',
    'swfTimedout': 'swf_timedout',
    'swfLoaded': 'swf_loaded',
    'swfUnblocked': 'swf_unblocked',
    'sm2Debug': 'sm2_debug',
    'highPerf': 'high_performance',
    'flashDebug': 'flash_debug'
  };
  if (_likesHTML5) {
    _s.useHTML5Audio = true;
    _s.preferFlash = false;
    if (_is_iDevice) {
      _s.ignoreFlash = true;
      _useGlobalHTML5Audio = true;
    }
  }
  this.ok = function() {
    return (_needsFlash?(_didInit && !_disabled):(_s.useHTML5Audio && _s.hasHTML5));
  };
  this.supported = this.ok;
  this.getMovie = function(smID) {
    return _id(smID) || _doc[smID] || _win[smID];
  };
  this.createSound = function(oOptions) {
    var _cs, _cs_string,
    thisOptions = null, oSound = null, _tO = null;
    if (!_didInit || !_s.ok()) {
      _complain(_cs_string);
      return false;
    }
    if (arguments.length === 2) {
      oOptions = {
        'id': arguments[0],
        'url': arguments[1]
      };
    }
    thisOptions = _mixin(oOptions);
    thisOptions.url = _parseURL(thisOptions.url);
    _tO = thisOptions;
    if (_idCheck(_tO.id, true)) {
      return _s.sounds[_tO.id];
    }
    function make() {
      thisOptions = _loopFix(thisOptions);
      _s.sounds[_tO.id] = new SMSound(_tO);
      _s.soundIDs.push(_tO.id);
      return _s.sounds[_tO.id];
    }
    if (_html5OK(_tO)) {
      oSound = make();
      oSound._setup_html5(_tO);
    } else {
      if (_fV > 8) {
        if (_tO.isMovieStar === null) {
          _tO.isMovieStar = (_tO.serverURL || (_tO.type ? _tO.type.match(_netStreamMimeTypes) : false) || _tO.url.match(_netStreamPattern));
        }
        if (_tO.isMovieStar) {
          if (_tO.usePeakData) {
            _tO.usePeakData = false;
          }
        }
      }
      _tO = _policyFix(_tO, _cs);
      oSound = make();
      if (_fV === 8) {
        _flash._createSound(_tO.id, _tO.loops||1, _tO.usePolicyFile);
      } else {
        _flash._createSound(_tO.id, _tO.url, _tO.usePeakData, _tO.useWaveformData, _tO.useEQData, _tO.isMovieStar, (_tO.isMovieStar?_tO.bufferTime:false), _tO.loops||1, _tO.serverURL, _tO.duration||null, _tO.autoPlay, true, _tO.autoLoad, _tO.usePolicyFile);
        if (!_tO.serverURL) {
          oSound.connected = true;
          if (_tO.onconnect) {
            _tO.onconnect.apply(oSound);
          }
        }
      }
      if (!_tO.serverURL && (_tO.autoLoad || _tO.autoPlay)) {
        oSound.load(_tO);
      }
    }
    if (!_tO.serverURL && _tO.autoPlay) {
      oSound.play();
    }
    return oSound;
  };
  this.destroySound = function(sID, _bFromSound) {
    if (!_idCheck(sID)) {
      return false;
    }
    var oS = _s.sounds[sID], i;
    oS._iO = {};
    oS.stop();
    oS.unload();
    for (i = 0; i < _s.soundIDs.length; i++) {
      if (_s.soundIDs[i] === sID) {
        _s.soundIDs.splice(i, 1);
        break;
      }
    }
    if (!_bFromSound) {
      oS.destruct(true);
    }
    oS = null;
    delete _s.sounds[sID];
    return true;
  };
  this.load = function(sID, oOptions) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].load(oOptions);
  };
  this.unload = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].unload();
  };
  this.onPosition = function(sID, nPosition, oMethod, oScope) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].onposition(nPosition, oMethod, oScope);
  };
  this.onposition = this.onPosition;
  this.clearOnPosition = function(sID, nPosition, oMethod) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].clearOnPosition(nPosition, oMethod);
  };
  this.play = function(sID, oOptions) {
    if (!_didInit || !_s.ok()) {
      _complain(_sm+'.play(): ' + _str(!_didInit?'notReady':'notOK'));
      return false;
    }
    if (!_idCheck(sID)) {
      if (!(oOptions instanceof Object)) {
        oOptions = {
          url: oOptions
        };
      }
      if (oOptions && oOptions.url) {
        oOptions.id = sID;
        return _s.createSound(oOptions).play();
      } else {
        return false;
      }
    }
    return _s.sounds[sID].play(oOptions);
  };
  this.start = this.play;
  this.setPosition = function(sID, nMsecOffset) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].setPosition(nMsecOffset);
  };
  this.stop = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].stop();
  };
  this.stopAll = function() {
    var oSound;
    for (oSound in _s.sounds) {
      if (_s.sounds.hasOwnProperty(oSound)) {
        _s.sounds[oSound].stop();
      }
    }
  };
  this.pause = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].pause();
  };
  this.pauseAll = function() {
    var i;
    for (i = _s.soundIDs.length; i--;) {
      _s.sounds[_s.soundIDs[i]].pause();
    }
  };
  this.resume = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].resume();
  };
  this.resumeAll = function() {
    var i;
    for (i = _s.soundIDs.length; i--;) {
      _s.sounds[_s.soundIDs[i]].resume();
    }
  };
  this.togglePause = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].togglePause();
  };
  this.setPan = function(sID, nPan) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].setPan(nPan);
  };
  this.setVolume = function(sID, nVol) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].setVolume(nVol);
  };
  this.mute = function(sID) {
    var i = 0;
    if (typeof sID !== 'string') {
      sID = null;
    }
    if (!sID) {
      for (i = _s.soundIDs.length; i--;) {
        _s.sounds[_s.soundIDs[i]].mute();
      }
      _s.muted = true;
    } else {
      if (!_idCheck(sID)) {
        return false;
      }
      return _s.sounds[sID].mute();
    }
    return true;
  };
  this.muteAll = function() {
    _s.mute();
  };
  this.unmute = function(sID) {
    var i;
    if (typeof sID !== 'string') {
      sID = null;
    }
    if (!sID) {
      for (i = _s.soundIDs.length; i--;) {
        _s.sounds[_s.soundIDs[i]].unmute();
      }
      _s.muted = false;
    } else {
      if (!_idCheck(sID)) {
        return false;
      }
      return _s.sounds[sID].unmute();
    }
    return true;
  };
  this.unmuteAll = function() {
    _s.unmute();
  };
  this.toggleMute = function(sID) {
    if (!_idCheck(sID)) {
      return false;
    }
    return _s.sounds[sID].toggleMute();
  };
  this.getMemoryUse = function() {
    var ram = 0;
    if (_flash && _fV !== 8) {
      ram = parseInt(_flash._getMemoryUse(), 10);
    }
    return ram;
  };
  this.disable = function(bNoDisable) {
    var i;
    if (typeof bNoDisable === 'undefined') {
      bNoDisable = false;
    }
    if (_disabled) {
      return false;
    }
    _disabled = true;
    for (i = _s.soundIDs.length; i--;) {
      _disableObject(_s.sounds[_s.soundIDs[i]]);
    }
    _initComplete(bNoDisable);
    _event.remove(_win, 'load', _initUserOnload);
    return true;
  };
  this.canPlayMIME = function(sMIME) {
    var result;
    if (_s.hasHTML5) {
      result = _html5CanPlay({type:sMIME});
    }
    if (!_needsFlash || result) {
      return result;
    } else {
      return (sMIME ? !!((_fV > 8 ? sMIME.match(_netStreamMimeTypes) : null) || sMIME.match(_s.mimePattern)) : null);
    }
  };
  this.canPlayURL = function(sURL) {
    var result;
    if (_s.hasHTML5) {
      result = _html5CanPlay({url: sURL});
    }
    if (!_needsFlash || result) {
      return result;
    } else {
      return (sURL ? !!(sURL.match(_s.filePattern)) : null);
    }
  };
  this.canPlayLink = function(oLink) {
    if (typeof oLink.type !== 'undefined' && oLink.type) {
      if (_s.canPlayMIME(oLink.type)) {
        return true;
      }
    }
    return _s.canPlayURL(oLink.href);
  };
  this.getSoundById = function(sID, _suppressDebug) {
    if (!sID) {
      throw new Error(_sm+'.getSoundById(): sID is null/undefined');
    }
    var result = _s.sounds[sID];
    return result;
  };
  this.onready = function(oMethod, oScope) {
    var sType = 'onready';
    if (oMethod && oMethod instanceof Function) {
      if (!oScope) {
        oScope = _win;
      }
      _addOnEvent(sType, oMethod, oScope);
      _processOnEvents();
      return true;
    } else {
      throw _str('needFunction', sType);
    }
  };
  this.ontimeout = function(oMethod, oScope) {
    var sType = 'ontimeout';
    if (oMethod && oMethod instanceof Function) {
      if (!oScope) {
        oScope = _win;
      }
      _addOnEvent(sType, oMethod, oScope);
      _processOnEvents({type:sType});
      return true;
    } else {
      throw _str('needFunction', sType);
    }
  };
  this._writeDebug = function(sText, sType, _bTimestamp) {
    return true;
  };
  this._wD = this._writeDebug;
  this._debug = function() {
  };
  this.reboot = function() {
    var i, j;
    for (i = _s.soundIDs.length; i--;) {
      _s.sounds[_s.soundIDs[i]].destruct();
    }
    try {
      if (_isIE) {
        _oRemovedHTML = _flash.innerHTML;
      }
      _oRemoved = _flash.parentNode.removeChild(_flash);
    } catch(e) {
    }
    _oRemovedHTML = _oRemoved = _needsFlash = null;
    _s.enabled = _didDCLoaded = _didInit = _waitingForEI = _initPending = _didAppend = _appendSuccess = _disabled = _s.swfLoaded = false;
    _s.soundIDs = _s.sounds = [];
    _flash = null;
    for (i in _on_queue) {
      if (_on_queue.hasOwnProperty(i)) {
        for (j = _on_queue[i].length; j--;) {
          _on_queue[i][j].fired = false;
        }
      }
    }
    _win.setTimeout(_s.beginDelayedInit, 20);
  };
  this.getMoviePercent = function() {
    return (_flash && typeof _flash.PercentLoaded !== 'undefined' ? _flash.PercentLoaded() : null);
  };
  this.beginDelayedInit = function() {
    _windowLoaded = true;
    _domContentLoaded();
    setTimeout(function() {
      if (_initPending) {
        return false;
      }
      _createMovie();
      _initMovie();
      _initPending = true;
      return true;
    }, 20);
    _delayWaitForEI();
  };
  this.destruct = function() {
    _s.disable(true);
  };
  SMSound = function(oOptions) {
    var _t = this, _resetProperties, _add_html5_events, _remove_html5_events, _stop_html5_timer, _start_html5_timer, _attachOnPosition, _onplay_called = false, _onPositionItems = [], _onPositionFired = 0, _detachOnPosition, _applyFromTo, _lastURL = null;
    var _lastHTML5State = {
      duration: null,
      time: null
    };
    this.sID = oOptions.id;
    this.url = oOptions.url;
    this.options = _mixin(oOptions);
    this.instanceOptions = this.options;
    this._iO = this.instanceOptions;
    this.pan = this.options.pan;
    this.volume = this.options.volume;
    this.isHTML5 = false;
    this._a = null;
    this.id3 = {};
    this._debug = function() {
    };
    this.load = function(oOptions) {
      var oS = null, _iO;
      if (typeof oOptions !== 'undefined') {
        _t._iO = _mixin(oOptions, _t.options);
        _t.instanceOptions = _t._iO;
      } else {
        oOptions = _t.options;
        _t._iO = oOptions;
        _t.instanceOptions = _t._iO;
        if (_lastURL && _lastURL !== _t.url) {
          _t._iO.url = _t.url;
          _t.url = null;
        }
      }
      if (!_t._iO.url) {
        _t._iO.url = _t.url;
      }
      _t._iO.url = _parseURL(_t._iO.url);
      if (_t._iO.url === _t.url && _t.readyState !== 0 && _t.readyState !== 2) {
        if (_t.readyState === 3 && _t._iO.onload) {
          _t._iO.onload.apply(_t, [(!!_t.duration)]);
        }
        return _t;
      }
      _iO = _t._iO;
      _lastURL = _t.url;
      _t.loaded = false;
      _t.readyState = 1;
      _t.playState = 0;
      if (_html5OK(_iO)) {
        oS = _t._setup_html5(_iO);
        if (!oS._called_load) {
          _t._html5_canplay = false;
          _t._a.autobuffer = 'auto';
          _t._a.preload = 'auto';
          oS.load();
          oS._called_load = true;
          if (_iO.autoPlay) {
            _t.play();
          }
        } else {
        }
      } else {
        try {
          _t.isHTML5 = false;
          _t._iO = _policyFix(_loopFix(_iO));
          _iO = _t._iO;
          if (_fV === 8) {
            _flash._load(_t.sID, _iO.url, _iO.stream, _iO.autoPlay, (_iO.whileloading?1:0), _iO.loops||1, _iO.usePolicyFile);
          } else {
            _flash._load(_t.sID, _iO.url, !!(_iO.stream), !!(_iO.autoPlay), _iO.loops||1, !!(_iO.autoLoad), _iO.usePolicyFile);
          }
        } catch(e) {
          _catchError({type:'SMSOUND_LOAD_JS_EXCEPTION', fatal:true});
        }
      }
      return _t;
    };
    this.unload = function() {
      if (_t.readyState !== 0) {
        if (!_t.isHTML5) {
          if (_fV === 8) {
            _flash._unload(_t.sID, _emptyURL);
          } else {
            _flash._unload(_t.sID);
          }
        } else {
          _stop_html5_timer();
          if (_t._a) {
            _t._a.pause();
            _html5Unload(_t._a);
          }
        }
        _resetProperties();
      }
      return _t;
    };
    this.destruct = function(_bFromSM) {
      if (!_t.isHTML5) {
        _t._iO.onfailure = null;
        _flash._destroySound(_t.sID);
      } else {
        _stop_html5_timer();
        if (_t._a) {
          _t._a.pause();
          _html5Unload(_t._a);
          if (!_useGlobalHTML5Audio) {
            _remove_html5_events();
          }
          _t._a._t = null;
          _t._a = null;
        }
      }
      if (!_bFromSM) {
        _s.destroySound(_t.sID, true);
      }
    };
    this.play = function(oOptions, _updatePlayState) {
      var fN, allowMulti, a, onready;
      _updatePlayState = _updatePlayState === undefined ? true : _updatePlayState;
      if (!oOptions) {
        oOptions = {};
      }
      _t._iO = _mixin(oOptions, _t._iO);
      _t._iO = _mixin(_t._iO, _t.options);
      _t._iO.url = _parseURL(_t._iO.url);
      _t.instanceOptions = _t._iO;
      if (_t._iO.serverURL && !_t.connected) {
        if (!_t.getAutoPlay()) {
          _t.setAutoPlay(true);
        }
        return _t;
      }
      if (_html5OK(_t._iO)) {
        _t._setup_html5(_t._iO);
        _start_html5_timer();
      }
      if (_t.playState === 1 && !_t.paused) {
        allowMulti = _t._iO.multiShot;
        if (!allowMulti) {
          return _t;
        } else {
        }
      }
      if (!_t.loaded) {
        if (_t.readyState === 0) {
          if (!_t.isHTML5) {
            _t._iO.autoPlay = true;
          }
          _t.load(_t._iO);
        } else if (_t.readyState === 2) {
          return _t;
        } else {
        }
      } else {
      }
      if (!_t.isHTML5 && _fV === 9 && _t.position > 0 && _t.position === _t.duration) {
        oOptions.position = 0;
      }
      if (_t.paused && _t.position && _t.position > 0) {
        _t.resume();
      } else {
        _t._iO = _mixin(oOptions, _t._iO);
        if (_t._iO.from !== null && _t._iO.to !== null && _t.instanceCount === 0 && _t.playState === 0 && !_t._iO.serverURL) {
          onready = function() {
            _t._iO = _mixin(oOptions, _t._iO);
            _t.play(_t._iO);
          };
          if (_t.isHTML5 && !_t._html5_canplay) {
            _t.load({
              _oncanplay: onready
            });
            return false;
          } else if (!_t.isHTML5 && !_t.loaded && (!_t.readyState || _t.readyState !== 2)) {
            _t.load({
              onload: onready
            });
            return false;
          }
          _t._iO = _applyFromTo();
        }
        if (!_t.instanceCount || _t._iO.multiShotEvents || (!_t.isHTML5 && _fV > 8 && !_t.getAutoPlay())) {
          _t.instanceCount++;
        }
        if (_t.playState === 0 && _t._iO.onposition) {
          _attachOnPosition(_t);
        }
        _t.playState = 1;
        _t.paused = false;
        _t.position = (typeof _t._iO.position !== 'undefined' && !isNaN(_t._iO.position) ? _t._iO.position : 0);
        if (!_t.isHTML5) {
          _t._iO = _policyFix(_loopFix(_t._iO));
        }
        if (_t._iO.onplay && _updatePlayState) {
          _t._iO.onplay.apply(_t);
          _onplay_called = true;
        }
        _t.setVolume(_t._iO.volume, true);
        _t.setPan(_t._iO.pan, true);
        if (!_t.isHTML5) {
          _flash._start(_t.sID, _t._iO.loops || 1, (_fV === 9?_t._iO.position:_t._iO.position / 1000));
        } else {
          _start_html5_timer();
          a = _t._setup_html5();
          _t.setPosition(_t._iO.position);
          a.play();
        }
      }
      return _t;
    };
    this.start = this.play;
    this.stop = function(bAll) {
      var _iO = _t._iO, _oP;
      if (_t.playState === 1) {
        _t._onbufferchange(0);
        _t._resetOnPosition(0);
        _t.paused = false;
        if (!_t.isHTML5) {
          _t.playState = 0;
        }
        _detachOnPosition();
        if (_iO.to) {
          _t.clearOnPosition(_iO.to);
        }
        if (!_t.isHTML5) {
          _flash._stop(_t.sID, bAll);
          if (_iO.serverURL) {
            _t.unload();
          }
        } else {
          if (_t._a) {
            _oP = _t.position;
            _t.setPosition(0);
            _t.position = _oP;
            _t._a.pause();
            _t.playState = 0;
            _t._onTimer();
            _stop_html5_timer();
          }
        }
        _t.instanceCount = 0;
        _t._iO = {};
        if (_iO.onstop) {
          _iO.onstop.apply(_t);
        }
      }
      return _t;
    };
    this.setAutoPlay = function(autoPlay) {
      _t._iO.autoPlay = autoPlay;
      if (!_t.isHTML5) {
        _flash._setAutoPlay(_t.sID, autoPlay);
        if (autoPlay) {
          if (!_t.instanceCount && _t.readyState === 1) {
            _t.instanceCount++;
          }
        }
      }
    };
    this.getAutoPlay = function() {
      return _t._iO.autoPlay;
    };
    this.setPosition = function(nMsecOffset) {
      if (nMsecOffset === undefined) {
        nMsecOffset = 0;
      }
      var original_pos,
          position, position1K,
          offset = (_t.isHTML5 ? Math.max(nMsecOffset,0) : Math.min(_t.duration || _t._iO.duration, Math.max(nMsecOffset, 0)));
      original_pos = _t.position;
      _t.position = offset;
      position1K = _t.position/1000;
      _t._resetOnPosition(_t.position);
      _t._iO.position = offset;
      if (!_t.isHTML5) {
        position = (_fV === 9 ? _t.position : position1K);
        if (_t.readyState && _t.readyState !== 2) {
          _flash._setPosition(_t.sID, position, (_t.paused || !_t.playState));
        }
      } else if (_t._a) {
        if (_t._html5_canplay) {
          if (_t._a.currentTime !== position1K) {
            try {
              _t._a.currentTime = position1K;
              if (_t.playState === 0 || _t.paused) {
                _t._a.pause();
              }
            } catch(e) {
            }
          }
        } else {
        }
      }
      if (_t.isHTML5) {
        if (_t.paused) {
          _t._onTimer(true);
        }
      }
      return _t;
    };
    this.pause = function(_bCallFlash) {
      if (_t.paused || (_t.playState === 0 && _t.readyState !== 1)) {
        return _t;
      }
      _t.paused = true;
      if (!_t.isHTML5) {
        if (_bCallFlash || _bCallFlash === undefined) {
          _flash._pause(_t.sID);
        }
      } else {
        _t._setup_html5().pause();
        _stop_html5_timer();
      }
      if (_t._iO.onpause) {
        _t._iO.onpause.apply(_t);
      }
      return _t;
    };
    this.resume = function() {
      var _iO = _t._iO;
      if (!_t.paused) {
        return _t;
      }
      _t.paused = false;
      _t.playState = 1;
      if (!_t.isHTML5) {
        if (_iO.isMovieStar && !_iO.serverURL) {
          _t.setPosition(_t.position);
        }
        _flash._pause(_t.sID);
      } else {
        _t._setup_html5().play();
        _start_html5_timer();
      }
      if (_onplay_called && _iO.onplay) {
        _iO.onplay.apply(_t);
        _onplay_called = true;
      } else if (_iO.onresume) {
        _iO.onresume.apply(_t);
      }
      return _t;
    };
    this.togglePause = function() {
      if (_t.playState === 0) {
        _t.play({
          position: (_fV === 9 && !_t.isHTML5 ? _t.position : _t.position / 1000)
        });
        return _t;
      }
      if (_t.paused) {
        _t.resume();
      } else {
        _t.pause();
      }
      return _t;
    };
    this.setPan = function(nPan, bInstanceOnly) {
      if (typeof nPan === 'undefined') {
        nPan = 0;
      }
      if (typeof bInstanceOnly === 'undefined') {
        bInstanceOnly = false;
      }
      if (!_t.isHTML5) {
        _flash._setPan(_t.sID, nPan);
      }
      _t._iO.pan = nPan;
      if (!bInstanceOnly) {
        _t.pan = nPan;
        _t.options.pan = nPan;
      }
      return _t;
    };
    this.setVolume = function(nVol, _bInstanceOnly) {
      if (typeof nVol === 'undefined') {
        nVol = 100;
      }
      if (typeof _bInstanceOnly === 'undefined') {
        _bInstanceOnly = false;
      }
      if (!_t.isHTML5) {
        _flash._setVolume(_t.sID, (_s.muted && !_t.muted) || _t.muted?0:nVol);
      } else if (_t._a) {
        _t._a.volume = Math.max(0, Math.min(1, nVol/100));
      }
      _t._iO.volume = nVol;
      if (!_bInstanceOnly) {
        _t.volume = nVol;
        _t.options.volume = nVol;
      }
      return _t;
    };
    this.mute = function() {
      _t.muted = true;
      if (!_t.isHTML5) {
        _flash._setVolume(_t.sID, 0);
      } else if (_t._a) {
        _t._a.muted = true;
      }
      return _t;
    };
    this.unmute = function() {
      _t.muted = false;
      var hasIO = typeof _t._iO.volume !== 'undefined';
      if (!_t.isHTML5) {
        _flash._setVolume(_t.sID, hasIO?_t._iO.volume:_t.options.volume);
      } else if (_t._a) {
        _t._a.muted = false;
      }
      return _t;
    };
    this.toggleMute = function() {
      return (_t.muted?_t.unmute():_t.mute());
    };
    this.onPosition = function(nPosition, oMethod, oScope) {
      _onPositionItems.push({
        position: nPosition,
        method: oMethod,
        scope: (typeof oScope !== 'undefined' ? oScope : _t),
        fired: false
      });
      return _t;
    };
    this.onposition = this.onPosition;
    this.clearOnPosition = function(nPosition, oMethod) {
      var i;
      nPosition = parseInt(nPosition, 10);
      if (isNaN(nPosition)) {
        return false;
      }
      for (i=0; i < _onPositionItems.length; i++) {
        if (nPosition === _onPositionItems[i].position) {
          if (!oMethod || (oMethod === _onPositionItems[i].method)) {
            if (_onPositionItems[i].fired) {
              _onPositionFired--;
            }
            _onPositionItems.splice(i, 1);
          }
        }
      }
    };
    this._processOnPosition = function() {
      var i, item, j = _onPositionItems.length;
      if (!j || !_t.playState || _onPositionFired >= j) {
        return false;
      }
      for (i=j; i--;) {
        item = _onPositionItems[i];
        if (!item.fired && _t.position >= item.position) {
          item.fired = true;
          _onPositionFired++;
          item.method.apply(item.scope, [item.position]);
        }
      }
      return true;
    };
    this._resetOnPosition = function(nPosition) {
      var i, item, j = _onPositionItems.length;
      if (!j) {
        return false;
      }
      for (i=j; i--;) {
        item = _onPositionItems[i];
        if (item.fired && nPosition <= item.position) {
          item.fired = false;
          _onPositionFired--;
        }
      }
      return true;
    };
    _applyFromTo = function() {
      var _iO = _t._iO,
          f = _iO.from,
          t = _iO.to,
          start, end;
      end = function() {
        _t.clearOnPosition(t, end);
        _t.stop();
      };
      start = function() {
        if (t !== null && !isNaN(t)) {
          _t.onPosition(t, end);
        }
      };
      if (f !== null && !isNaN(f)) {
        _iO.position = f;
        _iO.multiShot = false;
        start();
      }
      return _iO;
    };
    _attachOnPosition = function() {
      var op = _t._iO.onposition;
      if (op) {
        var item;
        for (item in op) {
          if (op.hasOwnProperty(item)) {
            _t.onPosition(parseInt(item, 10), op[item]);
          }
        }
      }
    };
    _detachOnPosition = function() {
      var op = _t._iO.onposition;
      if (op) {
        var item;
        for (item in op) {
          if (op.hasOwnProperty(item)) {
            _t.clearOnPosition(parseInt(item, 10));
          }
        }
      }
    };
    _start_html5_timer = function() {
      if (_t.isHTML5) {
        _startTimer(_t);
      }
    };
    _stop_html5_timer = function() {
      if (_t.isHTML5) {
        _stopTimer(_t);
      }
    };
    _resetProperties = function() {
      _onPositionItems = [];
      _onPositionFired = 0;
      _onplay_called = false;
      _t._hasTimer = null;
      _t._a = null;
      _t._html5_canplay = false;
      _t.bytesLoaded = null;
      _t.bytesTotal = null;
      _t.duration = (_t._iO && _t._iO.duration ? _t._iO.duration : null);
      _t.durationEstimate = null;
      _t.eqData = [];
      _t.eqData.left = [];
      _t.eqData.right = [];
      _t.failures = 0;
      _t.isBuffering = false;
      _t.instanceOptions = {};
      _t.instanceCount = 0;
      _t.loaded = false;
      _t.metadata = {};
      _t.readyState = 0;
      _t.muted = false;
      _t.paused = false;
      _t.peakData = {
        left: 0,
        right: 0
      };
      _t.waveformData = {
        left: [],
        right: []
      };
      _t.playState = 0;
      _t.position = null;
    };
    _resetProperties();
    this._onTimer = function(bForce) {
      var duration, isNew = false, time, x = {};
      if (_t._hasTimer || bForce) {
        if (_t._a && (bForce || ((_t.playState > 0 || _t.readyState === 1) && !_t.paused))) {
          duration = _t._get_html5_duration();
          if (duration !== _lastHTML5State.duration) {
            _lastHTML5State.duration = duration;
            _t.duration = duration;
            isNew = true;
          }
          _t.durationEstimate = _t.duration;
          time = (_t._a.currentTime * 1000 || 0);
          if (time !== _lastHTML5State.time) {
            _lastHTML5State.time = time;
            isNew = true;
          }
          if (isNew || bForce) {
            _t._whileplaying(time,x,x,x,x);
          }
          return isNew;
        } else {
          return false;
        }
      }
    };
    this._get_html5_duration = function() {
      var _iO = _t._iO,
          d = (_t._a ? _t._a.duration*1000 : (_iO ? _iO.duration : undefined)),
          result = (d && !isNaN(d) && d !== Infinity ? d : (_iO ? _iO.duration : null));
      return result;
    };
    this._setup_html5 = function(oOptions) {
      var _iO = _mixin(_t._iO, oOptions), d = decodeURI,
          _a = _useGlobalHTML5Audio ? _s._global_a : _t._a,
          _dURL = d(_iO.url),
          _oldIO = (_a && _a._t ? _a._t.instanceOptions : null);
      if (_a) {
        if (_a._t) {
          if (!_useGlobalHTML5Audio && _dURL === d(_lastURL)) {
            return _a;
          } else if (_useGlobalHTML5Audio && _oldIO.url === _iO.url && (!_lastURL || (_lastURL === _oldIO.url))) {
            return _a;
          }
        }
        if (_useGlobalHTML5Audio && _a._t && _a._t.playState && _iO.url !== _oldIO.url) {
          _a._t.stop();
        }
        _resetProperties();
        _a.src = _iO.url;
        _t.url = _iO.url;
        _lastURL = _iO.url;
        _a._called_load = false;
      } else {
        _a = new Audio(_iO.url);
        _a._called_load = false;
        if (_is_android) {
          _a._called_load = true;
        }
        if (_useGlobalHTML5Audio) {
          _s._global_a = _a;
        }
      }
      _t.isHTML5 = true;
      _t._a = _a;
      _a._t = _t;
      _add_html5_events();
      _a.loop = (_iO.loops>1?'loop':'');
      if (_iO.autoLoad || _iO.autoPlay) {
        _t.load();
      } else {
        _a.autobuffer = false;
        _a.preload = 'none';
      }
      _a.loop = (_iO.loops > 1 ? 'loop' : '');
      return _a;
    };
    _add_html5_events = function() {
      if (_t._a._added_events) {
        return false;
      }
      var f;
      function add(oEvt, oFn, bCapture) {
        return _t._a ? _t._a.addEventListener(oEvt, oFn, bCapture||false) : null;
      }
      _t._a._added_events = true;
      for (f in _html5_events) {
        if (_html5_events.hasOwnProperty(f)) {
          add(f, _html5_events[f]);
        }
      }
      return true;
    };
    _remove_html5_events = function() {
      var f;
      function remove(oEvt, oFn, bCapture) {
        return (_t._a ? _t._a.removeEventListener(oEvt, oFn, bCapture||false) : null);
      }
      _t._a._added_events = false;
      for (f in _html5_events) {
        if (_html5_events.hasOwnProperty(f)) {
          remove(f, _html5_events[f]);
        }
      }
    };
    this._onload = function(nSuccess) {
      var fN, loadOK = !!(nSuccess);
      _t.loaded = loadOK;
      _t.readyState = loadOK?3:2;
      _t._onbufferchange(0);
      if (_t._iO.onload) {
        _t._iO.onload.apply(_t, [loadOK]);
      }
      return true;
    };
    this._onbufferchange = function(nIsBuffering) {
      if (_t.playState === 0) {
        return false;
      }
      if ((nIsBuffering && _t.isBuffering) || (!nIsBuffering && !_t.isBuffering)) {
        return false;
      }
      _t.isBuffering = (nIsBuffering === 1);
      if (_t._iO.onbufferchange) {
        _t._iO.onbufferchange.apply(_t);
      }
      return true;
    };
    this._onsuspend = function() {
      if (_t._iO.onsuspend) {
        _t._iO.onsuspend.apply(_t);
      }
      return true;
    };
    this._onfailure = function(msg, level, code) {
      _t.failures++;
      if (_t._iO.onfailure && _t.failures === 1) {
        _t._iO.onfailure(_t, msg, level, code);
      } else {
      }
    };
    this._onfinish = function() {
      var _io_onfinish = _t._iO.onfinish;
      _t._onbufferchange(0);
      _t._resetOnPosition(0);
      if (_t.instanceCount) {
        _t.instanceCount--;
        if (!_t.instanceCount) {
          _detachOnPosition();
          _t.playState = 0;
          _t.paused = false;
          _t.instanceCount = 0;
          _t.instanceOptions = {};
          _t._iO = {};
          _stop_html5_timer();
        }
        if (!_t.instanceCount || _t._iO.multiShotEvents) {
          if (_io_onfinish) {
            _io_onfinish.apply(_t);
          }
        }
      }
    };
    this._whileloading = function(nBytesLoaded, nBytesTotal, nDuration, nBufferLength) {
      var _iO = _t._iO;
      _t.bytesLoaded = nBytesLoaded;
      _t.bytesTotal = nBytesTotal;
      _t.duration = Math.floor(nDuration);
      _t.bufferLength = nBufferLength;
      if (!_iO.isMovieStar) {
        if (_iO.duration) {
          _t.durationEstimate = (_t.duration > _iO.duration) ? _t.duration : _iO.duration;
        } else {
          _t.durationEstimate = parseInt((_t.bytesTotal / _t.bytesLoaded) * _t.duration, 10);
        }
        if (_t.durationEstimate === undefined) {
          _t.durationEstimate = _t.duration;
        }
        if (_t.readyState !== 3 && _iO.whileloading) {
          _iO.whileloading.apply(_t);
        }
      } else {
        _t.durationEstimate = _t.duration;
        if (_t.readyState !== 3 && _iO.whileloading) {
          _iO.whileloading.apply(_t);
        }
      }
    };
    this._whileplaying = function(nPosition, oPeakData, oWaveformDataLeft, oWaveformDataRight, oEQData) {
      var _iO = _t._iO;
      if (isNaN(nPosition) || nPosition === null) {
        return false;
      }
      _t.position = nPosition;
      _t._processOnPosition();
      if (!_t.isHTML5 && _fV > 8) {
        if (_iO.usePeakData && typeof oPeakData !== 'undefined' && oPeakData) {
          _t.peakData = {
            left: oPeakData.leftPeak,
            right: oPeakData.rightPeak
          };
        }
        if (_iO.useWaveformData && typeof oWaveformDataLeft !== 'undefined' && oWaveformDataLeft) {
          _t.waveformData = {
            left: oWaveformDataLeft.split(','),
            right: oWaveformDataRight.split(',')
          };
        }
        if (_iO.useEQData) {
          if (typeof oEQData !== 'undefined' && oEQData && oEQData.leftEQ) {
            var eqLeft = oEQData.leftEQ.split(',');
            _t.eqData = eqLeft;
            _t.eqData.left = eqLeft;
            if (typeof oEQData.rightEQ !== 'undefined' && oEQData.rightEQ) {
              _t.eqData.right = oEQData.rightEQ.split(',');
            }
          }
        }
      }
      if (_t.playState === 1) {
        if (!_t.isHTML5 && _fV === 8 && !_t.position && _t.isBuffering) {
          _t._onbufferchange(0);
        }
        if (_iO.whileplaying) {
          _iO.whileplaying.apply(_t);
        }
      }
      return true;
    };
    this._onmetadata = function(oMDProps, oMDData) {
      var oData = {}, i, j;
      for (i = 0, j = oMDProps.length; i < j; i++) {
        oData[oMDProps[i]] = oMDData[i];
      }
      _t.metadata = oData;
      if (_t._iO.onmetadata) {
        _t._iO.onmetadata.apply(_t);
      }
	};
    this._onid3 = function(oID3Props, oID3Data) {
      var oData = [], i, j;
      for (i = 0, j = oID3Props.length; i < j; i++) {
        oData[oID3Props[i]] = oID3Data[i];
      }
      _t.id3 = _mixin(_t.id3, oData);
      if (_t._iO.onid3) {
        _t._iO.onid3.apply(_t);
      }
    };
    this._onconnect = function(bSuccess) {
      bSuccess = (bSuccess === 1);
      _t.connected = bSuccess;
      if (bSuccess) {
        _t.failures = 0;
        if (_idCheck(_t.sID)) {
          if (_t.getAutoPlay()) {
            _t.play(undefined, _t.getAutoPlay());
          } else if (_t._iO.autoLoad) {
            _t.load();
          }
        }
        if (_t._iO.onconnect) {
          _t._iO.onconnect.apply(_t, [bSuccess]);
        }
      }
    };
    this._ondataerror = function(sError) {
      if (_t.playState > 0) {
        if (_t._iO.ondataerror) {
          _t._iO.ondataerror.apply(_t);
        }
      }
    };
  };
  _getDocument = function() {
    return (_doc.body || _doc._docElement || _doc.getElementsByTagName('div')[0]);
  };
  _id = function(sID) {
    return _doc.getElementById(sID);
  };
  _mixin = function(oMain, oAdd) {
    var o1 = {}, i, o2, o;
    for (i in oMain) {
      if (oMain.hasOwnProperty(i)) {
        o1[i] = oMain[i];
      }
    }
    o2 = (typeof oAdd === 'undefined'?_s.defaultOptions:oAdd);
    for (o in o2) {
      if (o2.hasOwnProperty(o) && typeof o1[o] === 'undefined') {
        o1[o] = o2[o];
      }
    }
    return o1;
  };
  _event = (function() {
    var old = (_win.attachEvent),
    evt = {
      add: (old?'attachEvent':'addEventListener'),
      remove: (old?'detachEvent':'removeEventListener')
    };
    function getArgs(oArgs) {
      var args = _slice.call(oArgs), len = args.length;
      if (old) {
        args[1] = 'on' + args[1];
        if (len > 3) {
          args.pop();
        }
      } else if (len === 3) {
        args.push(false);
      }
      return args;
    }
    function apply(args, sType) {
      var element = args.shift(),
          method = [evt[sType]];
      if (old) {
        element[method](args[0], args[1]);
      } else {
        element[method].apply(element, args);
      }
    }
    function add() {
      apply(getArgs(arguments), 'add');
    }
    function remove() {
      apply(getArgs(arguments), 'remove');
    }
    return {
      'add': add,
      'remove': remove
    };
  }());
  function _html5_event(oFn) {
    return function(e) {
      var t = this._t;
      if (!t || !t._a) {
        return null;
      } else {
        return oFn.call(this, e);
      }
    };
  }
  _html5_events = {
    abort: _html5_event(function(e) {
    }),
    canplay: _html5_event(function(e) {
      var t = this._t;
      if (t._html5_canplay) {
        return true;
      }
      t._html5_canplay = true;
      t._onbufferchange(0);
      var position1K = (!isNaN(t.position)?t.position/1000:null);
      if (t.position && this.currentTime !== position1K) {
        try {
          this.currentTime = position1K;
        } catch(ee) {
        }
      }
      if (t._iO._oncanplay) {
        t._iO._oncanplay();
      }
    }),
    load: _html5_event(function(e) {
      var t = this._t;
      if (!t.loaded) {
        t._onbufferchange(0);
        t._whileloading(t.bytesTotal, t.bytesTotal, t._get_html5_duration());
        t._onload(true);
      }
    }),
    emptied: _html5_event(function(e) {
    }),
    ended: _html5_event(function(e) {
      var t = this._t;
      t._onfinish();
    }),
    error: _html5_event(function(e) {
      this._t._onload(false);
    }),
    loadeddata: _html5_event(function(e) {
      var t = this._t,
          bytesTotal = t.bytesTotal || 1;
      if (!t._loaded && !_isSafari) {
        t.duration = t._get_html5_duration();
        t._whileloading(bytesTotal, bytesTotal, t._get_html5_duration());
        t._onload(true);
      }
    }),
    loadedmetadata: _html5_event(function(e) {
    }),
    loadstart: _html5_event(function(e) {
      this._t._onbufferchange(1);
    }),
    play: _html5_event(function(e) {
      this._t._onbufferchange(0);
    }),
    playing: _html5_event(function(e) {
      this._t._onbufferchange(0);
    }),
    progress: _html5_event(function(e) {
      var t = this._t;
      if (t.loaded) {
        return false;
      }
      var i, j, str, buffered = 0,
          isProgress = (e.type === 'progress'),
          ranges = e.target.buffered,
          loaded = (e.loaded||0),
          total = (e.total||1);
      if (ranges && ranges.length) {
        for (i=ranges.length; i--;) {
          buffered = (ranges.end(i) - ranges.start(i));
        }
        loaded = buffered/e.target.duration;
      }
      if (!isNaN(loaded)) {
        t._onbufferchange(0);
        t._whileloading(loaded, total, t._get_html5_duration());
        if (loaded && total && loaded === total) {
          _html5_events.load.call(this, e);
        }
      }
    }),
    ratechange: _html5_event(function(e) {
    }),
    suspend: _html5_event(function(e) {
      var t = this._t;
      _html5_events.progress.call(this, e);
      t._onsuspend();
    }),
    stalled: _html5_event(function(e) {
    }),
    timeupdate: _html5_event(function(e) {
      this._t._onTimer();
    }),
    waiting: _html5_event(function(e) {
      var t = this._t;
      t._onbufferchange(1);
    })
  };
  _html5OK = function(iO) {
    return (!iO.serverURL && (iO.type?_html5CanPlay({type:iO.type}):_html5CanPlay({url:iO.url})||_s.html5Only));
  };
  _html5Unload = function(oAudio) {
    if (oAudio) {
      oAudio.src = (_is_firefox ? '' : _emptyURL);
    }
  };
  _html5CanPlay = function(o) {
    if (!_s.useHTML5Audio || !_s.hasHTML5) {
      return false;
    }
    var url = (o.url || null),
        mime = (o.type || null),
        aF = _s.audioFormats,
        result,
        offset,
        fileExt,
        item;
    function preferFlashCheck(kind) {
      return (_s.preferFlash && _hasFlash && !_s.ignoreFlash && (typeof _s.flash[kind] !== 'undefined' && _s.flash[kind]));
    }
    if (mime && _s.html5[mime] !== 'undefined') {
      return (_s.html5[mime] && !preferFlashCheck(mime));
    }
    if (!_html5Ext) {
      _html5Ext = [];
      for (item in aF) {
        if (aF.hasOwnProperty(item)) {
          _html5Ext.push(item);
          if (aF[item].related) {
            _html5Ext = _html5Ext.concat(aF[item].related);
          }
        }
      }
      _html5Ext = new RegExp('\\.('+_html5Ext.join('|')+')(\\?.*)?$','i');
    }
    fileExt = (url ? url.toLowerCase().match(_html5Ext) : null);
    if (!fileExt || !fileExt.length) {
      if (!mime) {
        return false;
      } else {
        offset = mime.indexOf(';');
        fileExt = (offset !== -1?mime.substr(0,offset):mime).substr(6);
      }
    } else {
      fileExt = fileExt[1];
    }
    if (fileExt && typeof _s.html5[fileExt] !== 'undefined') {
      return (_s.html5[fileExt] && !preferFlashCheck(fileExt));
    } else {
      mime = 'audio/'+fileExt;
      result = _s.html5.canPlayType({type:mime});
      _s.html5[fileExt] = result;
      return (result && _s.html5[mime] && !preferFlashCheck(mime));
    }
  };
  _testHTML5 = function() {
    if (!_s.useHTML5Audio || typeof Audio === 'undefined') {
      return false;
    }
    var a = (typeof Audio !== 'undefined' ? (_isOpera ? new Audio(null) : new Audio()) : null),
        item, support = {}, aF, i;
    function _cp(m) {
      var canPlay, i, j, isOK = false;
      if (!a || typeof a.canPlayType !== 'function') {
        return false;
      }
      if (m instanceof Array) {
        for (i=0, j=m.length; i<j && !isOK; i++) {
          if (_s.html5[m[i]] || a.canPlayType(m[i]).match(_s.html5Test)) {
            isOK = true;
            _s.html5[m[i]] = true;
            _s.flash[m[i]] = !!(_s.preferFlash && _hasFlash && m[i].match(_flashMIME));
          }
        }
        return isOK;
      } else {
        canPlay = (a && typeof a.canPlayType === 'function' ? a.canPlayType(m) : false);
        return !!(canPlay && (canPlay.match(_s.html5Test)));
      }
    }
    aF = _s.audioFormats;
    for (item in aF) {
      if (aF.hasOwnProperty(item)) {
        support[item] = _cp(aF[item].type);
        support['audio/'+item] = support[item];
        if (_s.preferFlash && !_s.ignoreFlash && item.match(_flashMIME)) {
          _s.flash[item] = true;
        } else {
          _s.flash[item] = false;
        }
        if (aF[item] && aF[item].related) {
          for (i=aF[item].related.length; i--;) {
            support['audio/'+aF[item].related[i]] = support[item];
            _s.html5[aF[item].related[i]] = support[item];
            _s.flash[aF[item].related[i]] = support[item];
          }
        }
      }
    }
    support.canPlayType = (a?_cp:null);
    _s.html5 = _mixin(_s.html5, support);
    return true;
  };
  _strings = {
  };
  _str = function() {
  };
  _loopFix = function(sOpt) {
    if (_fV === 8 && sOpt.loops > 1 && sOpt.stream) {
      sOpt.stream = false;
    }
    return sOpt;
  };
  _policyFix = function(sOpt, sPre) {
    if (sOpt && !sOpt.usePolicyFile && (sOpt.onid3 || sOpt.usePeakData || sOpt.useWaveformData || sOpt.useEQData)) {
      sOpt.usePolicyFile = true;
    }
    return sOpt;
  };
  _complain = function(sMsg) {
  };
  _doNothing = function() {
    return false;
  };
  _disableObject = function(o) {
    var oProp;
    for (oProp in o) {
      if (o.hasOwnProperty(oProp) && typeof o[oProp] === 'function') {
        o[oProp] = _doNothing;
      }
    }
    oProp = null;
  };
  _failSafely = function(bNoDisable) {
    if (typeof bNoDisable === 'undefined') {
      bNoDisable = false;
    }
    if (_disabled || bNoDisable) {
      _s.disable(bNoDisable);
    }
  };
  _normalizeMovieURL = function(smURL) {
    var urlParams = null, url;
    if (smURL) {
      if (smURL.match(/\.swf(\?.*)?$/i)) {
        urlParams = smURL.substr(smURL.toLowerCase().lastIndexOf('.swf?') + 4);
        if (urlParams) {
          return smURL;
        }
      } else if (smURL.lastIndexOf('/') !== smURL.length - 1) {
        smURL += '/';
      }
    }
    url = (smURL && smURL.lastIndexOf('/') !== - 1 ? smURL.substr(0, smURL.lastIndexOf('/') + 1) : './') + _s.movieURL;
    if (_s.noSWFCache) {
      url += ('?ts=' + new Date().getTime());
    }
    return url;
  };
  _setVersionInfo = function() {
    _fV = parseInt(_s.flashVersion, 10);
    if (_fV !== 8 && _fV !== 9) {
      _s.flashVersion = _fV = _defaultFlashVersion;
    }
    var isDebug = (_s.debugMode || _s.debugFlash?'_debug.swf':'.swf');
    if (_s.useHTML5Audio && !_s.html5Only && _s.audioFormats.mp4.required && _fV < 9) {
      _s.flashVersion = _fV = 9;
    }
    _s.version = _s.versionNumber + (_s.html5Only?' (HTML5-only mode)':(_fV === 9?' (AS3/Flash 9)':' (AS2/Flash 8)'));
    if (_fV > 8) {
      _s.defaultOptions = _mixin(_s.defaultOptions, _s.flash9Options);
      _s.features.buffering = true;
      _s.defaultOptions = _mixin(_s.defaultOptions, _s.movieStarOptions);
      _s.filePatterns.flash9 = new RegExp('\\.(mp3|' + _netStreamTypes.join('|') + ')(\\?.*)?$', 'i');
      _s.features.movieStar = true;
    } else {
      _s.features.movieStar = false;
    }
    _s.filePattern = _s.filePatterns[(_fV !== 8?'flash9':'flash8')];
    _s.movieURL = (_fV === 8?'soundmanager2.swf':'soundmanager2_flash9.swf').replace('.swf', isDebug);
    _s.features.peakData = _s.features.waveformData = _s.features.eqData = (_fV > 8);
  };
  _setPolling = function(bPolling, bHighPerformance) {
    if (!_flash) {
      return false;
    }
    _flash._setPolling(bPolling, bHighPerformance);
  };
  _initDebug = function() {
    if (_s.debugURLParam.test(_wl)) {
      _s.debugMode = true;
    }
  };
  _idCheck = this.getSoundById;
  _getSWFCSS = function() {
    var css = [];
    if (_s.debugMode) {
      css.push(_swfCSS.sm2Debug);
    }
    if (_s.debugFlash) {
      css.push(_swfCSS.flashDebug);
    }
    if (_s.useHighPerformance) {
      css.push(_swfCSS.highPerf);
    }
    return css.join(' ');
  };
  _flashBlockHandler = function() {
    var name = _str('fbHandler'),
        p = _s.getMoviePercent(),
        css = _swfCSS,
        error = {type:'FLASHBLOCK'};
    if (_s.html5Only) {
      return false;
    }
    if (!_s.ok()) {
      if (_needsFlash) {
        _s.oMC.className = _getSWFCSS() + ' ' + css.swfDefault + ' ' + (p === null?css.swfTimedout:css.swfError);
      }
      _s.didFlashBlock = true;
      _processOnEvents({type:'ontimeout', ignoreInit:true, error:error});
      _catchError(error);
    } else {
      if (_s.oMC) {
        _s.oMC.className = [_getSWFCSS(), css.swfDefault, css.swfLoaded + (_s.didFlashBlock?' '+css.swfUnblocked:'')].join(' ');
      }
    }
  };
  _addOnEvent = function(sType, oMethod, oScope) {
    if (typeof _on_queue[sType] === 'undefined') {
      _on_queue[sType] = [];
    }
    _on_queue[sType].push({
      'method': oMethod,
      'scope': (oScope || null),
      'fired': false
    });
  };
  _processOnEvents = function(oOptions) {
    if (!oOptions) {
      oOptions = {
        type: 'onready'
      };
    }
    if (!_didInit && oOptions && !oOptions.ignoreInit) {
      return false;
    }
    if (oOptions.type === 'ontimeout' && _s.ok()) {
      return false;
    }
    var status = {
          success: (oOptions && oOptions.ignoreInit?_s.ok():!_disabled)
        },
        srcQueue = (oOptions && oOptions.type?_on_queue[oOptions.type]||[]:[]),
        queue = [], i, j,
        args = [status],
        canRetry = (_needsFlash && _s.useFlashBlock && !_s.ok());
    if (oOptions.error) {
      args[0].error = oOptions.error;
    }
    for (i = 0, j = srcQueue.length; i < j; i++) {
      if (srcQueue[i].fired !== true) {
        queue.push(srcQueue[i]);
      }
    }
    if (queue.length) {
      for (i = 0, j = queue.length; i < j; i++) {
        if (queue[i].scope) {
          queue[i].method.apply(queue[i].scope, args);
        } else {
          queue[i].method.apply(this, args);
        }
        if (!canRetry) {
          queue[i].fired = true;
        }
      }
    }
    return true;
  };
  _initUserOnload = function() {
    _win.setTimeout(function() {
      if (_s.useFlashBlock) {
        _flashBlockHandler();
      }
      _processOnEvents();
      if (_s.onload instanceof Function) {
        _s.onload.apply(_win);
      }
      if (_s.waitForWindowLoad) {
        _event.add(_win, 'load', _initUserOnload);
      }
    },1);
  };
  _detectFlash = function() {
    if (_hasFlash !== undefined) {
      return _hasFlash;
    }
    var hasPlugin = false, n = navigator, nP = n.plugins, obj, type, types, AX = _win.ActiveXObject;
    if (nP && nP.length) {
      type = 'application/x-shockwave-flash';
      types = n.mimeTypes;
      if (types && types[type] && types[type].enabledPlugin && types[type].enabledPlugin.description) {
        hasPlugin = true;
      }
    } else if (typeof AX !== 'undefined') {
      try {
        obj = new AX('ShockwaveFlash.ShockwaveFlash');
      } catch(e) {
      }
      hasPlugin = (!!obj);
    }
    _hasFlash = hasPlugin;
    return hasPlugin;
  };
  _featureCheck = function() {
    var needsFlash, item,
        isSpecial = (_is_iDevice && !!(_ua.match(/os (1|2|3_0|3_1)/i)));
    if (isSpecial) {
      _s.hasHTML5 = false;
      _s.html5Only = true;
      if (_s.oMC) {
        _s.oMC.style.display = 'none';
      }
      return false;
    }
    if (_s.useHTML5Audio) {
      if (!_s.html5 || !_s.html5.canPlayType) {
        _s.hasHTML5 = false;
        return true;
      } else {
        _s.hasHTML5 = true;
      }
      if (_isBadSafari) {
        if (_detectFlash()) {
          return true;
        }
      }
    } else {
      return true;
    }
    for (item in _s.audioFormats) {
      if (_s.audioFormats.hasOwnProperty(item)) {
        if ((_s.audioFormats[item].required && !_s.html5.canPlayType(_s.audioFormats[item].type)) || _s.flash[item] || _s.flash[_s.audioFormats[item].type]) {
          needsFlash = true;
        }
      }
    }
    if (_s.ignoreFlash) {
      needsFlash = false;
    }
    _s.html5Only = (_s.hasHTML5 && _s.useHTML5Audio && !needsFlash);
    return (!_s.html5Only);
  };
  _parseURL = function(url) {
    var i, j, result = 0;
    if (url instanceof Array) {
      for (i=0, j=url.length; i<j; i++) {
        if (url[i] instanceof Object) {
          if (_s.canPlayMIME(url[i].type)) {
            result = i;
            break;
          }
        } else if (_s.canPlayURL(url[i])) {
          result = i;
          break;
        }
      }
      if (url[result].url) {
        url[result] = url[result].url;
      }
      return url[result];
    } else {
      return url;
    }
  };
  _startTimer = function(oSound) {
    if (!oSound._hasTimer) {
      oSound._hasTimer = true;
      if (!_likesHTML5 && _s.html5PollingInterval) {
        if (_h5IntervalTimer === null && _h5TimerCount === 0) {
          _h5IntervalTimer = window.setInterval(_timerExecute, _s.html5PollingInterval);
        }
        _h5TimerCount++;
      }
    }
  };
  _stopTimer = function(oSound) {
    if (oSound._hasTimer) {
      oSound._hasTimer = false;
      if (!_likesHTML5 && _s.html5PollingInterval) {
        _h5TimerCount--;
      }
    }
  };
  _timerExecute = function() {
    var i, j;
    if (_h5IntervalTimer !== null && !_h5TimerCount) {
      window.clearInterval(_h5IntervalTimer);
      _h5IntervalTimer = null;
      return false;
    }
    for (i = _s.soundIDs.length; i--;) {
      if (_s.sounds[_s.soundIDs[i]].isHTML5 && _s.sounds[_s.soundIDs[i]]._hasTimer) {
        _s.sounds[_s.soundIDs[i]]._onTimer();
      }
    }
  };
  _catchError = function(options) {
    options = (typeof options !== 'undefined' ? options : {});
    if (_s.onerror instanceof Function) {
      _s.onerror.apply(_win, [{type:(typeof options.type !== 'undefined' ? options.type : null)}]);
    }
    if (typeof options.fatal !== 'undefined' && options.fatal) {
      _s.disable();
    }
  };
  _badSafariFix = function() {
    if (!_isBadSafari || !_detectFlash()) {
      return false;
    }
    var aF = _s.audioFormats, i, item;
    for (item in aF) {
      if (aF.hasOwnProperty(item)) {
        if (item === 'mp3' || item === 'mp4') {
          _s.html5[item] = false;
          if (aF[item] && aF[item].related) {
            for (i = aF[item].related.length; i--;) {
              _s.html5[aF[item].related[i]] = false;
            }
          }
        }
      }
    }
  };
  this._setSandboxType = function(sandboxType) {
  };
  this._externalInterfaceOK = function(flashDate, swfVersion) {
    if (_s.swfLoaded) {
      return false;
    }
    var e, eiTime = new Date().getTime();
    _s.swfLoaded = true;
    _tryInitOnFocus = false;
    if (_isBadSafari) {
      _badSafariFix();
    }
    if (_isIE) {
      setTimeout(_init, 100);
    } else {
      _init();
    }
  };
  _createMovie = function(smID, smURL) {
    if (_didAppend && _appendSuccess) {
      return false;
    }
    function _initMsg() {
    }
    if (_s.html5Only) {
      _setVersionInfo();
      _initMsg();
      _s.oMC = _id(_s.movieID);
      _init();
      _didAppend = true;
      _appendSuccess = true;
      return false;
    }
    var remoteURL = (smURL || _s.url),
    localURL = (_s.altURL || remoteURL),
    swfTitle = 'JS/Flash audio component (SoundManager 2)',
    oEmbed, oMovie, oTarget = _getDocument(), tmp, movieHTML, oEl, extraClass = _getSWFCSS(),
    s, x, sClass, side = 'auto', isRTL = null,
    html = _doc.getElementsByTagName('html')[0];
    isRTL = (html && html.dir && html.dir.match(/rtl/i));
    smID = (typeof smID === 'undefined'?_s.id:smID);
    function param(name, value) {
      return '<param name="'+name+'" value="'+value+'" />';
    }
    _setVersionInfo();
    _s.url = _normalizeMovieURL(_overHTTP?remoteURL:localURL);
    smURL = _s.url;
    _s.wmode = (!_s.wmode && _s.useHighPerformance ? 'transparent' : _s.wmode);
    if (_s.wmode !== null && (_ua.match(/msie 8/i) || (!_isIE && !_s.useHighPerformance)) && navigator.platform.match(/win32|win64/i)) {
      _s.wmode = null;
    }
    oEmbed = {
      'name': smID,
      'id': smID,
      'src': smURL,
      'width': side,
      'height': side,
      'quality': 'high',
      'allowScriptAccess': _s.allowScriptAccess,
      'bgcolor': _s.bgColor,
      'pluginspage': _http+'www.macromedia.com/go/getflashplayer',
      'title': swfTitle,
      'type': 'application/x-shockwave-flash',
      'wmode': _s.wmode,
      'hasPriority': 'true'
    };
    if (_s.debugFlash) {
      oEmbed.FlashVars = 'debug=1';
    }
    if (!_s.wmode) {
      delete oEmbed.wmode;
    }
    if (_isIE) {
      oMovie = _doc.createElement('div');
      movieHTML = [
        '<object id="' + smID + '" data="' + smURL + '" type="' + oEmbed.type + '" title="' + oEmbed.title +'" classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="' + _http+'download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,40,0" width="' + oEmbed.width + '" height="' + oEmbed.height + '">',
        param('movie', smURL),
        param('AllowScriptAccess', _s.allowScriptAccess),
        param('quality', oEmbed.quality),
        (_s.wmode? param('wmode', _s.wmode): ''),
        param('bgcolor', _s.bgColor),
        param('hasPriority', 'true'),
        (_s.debugFlash ? param('FlashVars', oEmbed.FlashVars) : ''),
        '</object>'
      ].join('');
    } else {
      oMovie = _doc.createElement('embed');
      for (tmp in oEmbed) {
        if (oEmbed.hasOwnProperty(tmp)) {
          oMovie.setAttribute(tmp, oEmbed[tmp]);
        }
      }
    }
    _initDebug();
    extraClass = _getSWFCSS();
    oTarget = _getDocument();
    if (oTarget) {
      _s.oMC = (_id(_s.movieID) || _doc.createElement('div'));
      if (!_s.oMC.id) {
        _s.oMC.id = _s.movieID;
        _s.oMC.className = _swfCSS.swfDefault + ' ' + extraClass;
        s = null;
        oEl = null;
        if (!_s.useFlashBlock) {
          if (_s.useHighPerformance) {
            s = {
              'position': 'fixed',
              'width': '8px',
              'height': '8px',
              'bottom': '0px',
              'left': '0px',
              'overflow': 'hidden'
            };
          } else {
            s = {
              'position': 'absolute',
              'width': '6px',
              'height': '6px',
              'top': '-9999px',
              'left': '-9999px'
            };
            if (isRTL) {
              s.left = Math.abs(parseInt(s.left,10))+'px';
            }
          }
        }
        if (_isWebkit) {
          _s.oMC.style.zIndex = 10000;
        }
        if (!_s.debugFlash) {
          for (x in s) {
            if (s.hasOwnProperty(x)) {
              _s.oMC.style[x] = s[x];
            }
          }
        }
        try {
          if (!_isIE) {
            _s.oMC.appendChild(oMovie);
          }
          oTarget.appendChild(_s.oMC);
          if (_isIE) {
            oEl = _s.oMC.appendChild(_doc.createElement('div'));
            oEl.className = _swfCSS.swfBox;
            oEl.innerHTML = movieHTML;
          }
          _appendSuccess = true;
        } catch(e) {
          throw new Error(_str('domError')+' \n'+e.toString());
        }
      } else {
        sClass = _s.oMC.className;
        _s.oMC.className = (sClass?sClass+' ':_swfCSS.swfDefault) + (extraClass?' '+extraClass:'');
        _s.oMC.appendChild(oMovie);
        if (_isIE) {
          oEl = _s.oMC.appendChild(_doc.createElement('div'));
          oEl.className = _swfCSS.swfBox;
          oEl.innerHTML = movieHTML;
        }
        _appendSuccess = true;
      }
    }
    _didAppend = true;
    _initMsg();
    return true;
  };
  _initMovie = function() {
    if (_s.html5Only) {
      _createMovie();
      return false;
    }
    if (_flash) {
      return false;
    }
    _flash = _s.getMovie(_s.id);
    if (!_flash) {
      if (!_oRemoved) {
        _createMovie(_s.id, _s.url);
      } else {
        if (!_isIE) {
          _s.oMC.appendChild(_oRemoved);
        } else {
          _s.oMC.innerHTML = _oRemovedHTML;
        }
        _oRemoved = null;
        _didAppend = true;
      }
      _flash = _s.getMovie(_s.id);
    }
    if (_s.oninitmovie instanceof Function) {
      setTimeout(_s.oninitmovie, 1);
    }
    return true;
  };
  _delayWaitForEI = function() {
    setTimeout(_waitForEI, 1000);
  };
  _waitForEI = function() {
    if (_waitingForEI) {
      return false;
    }
    _waitingForEI = true;
    _event.remove(_win, 'load', _delayWaitForEI);
    if (_tryInitOnFocus && !_isFocused) {
      return false;
    }
    var p;
    if (!_didInit) {
      p = _s.getMoviePercent();
    }
    setTimeout(function() {
      p = _s.getMoviePercent();
      if (!_didInit && _okToDisable) {
        if (p === null) {
          if (_s.useFlashBlock || _s.flashLoadTimeout === 0) {
            if (_s.useFlashBlock) {
              _flashBlockHandler();
            }
          } else {
            _failSafely(true);
          }
        } else {
          if (_s.flashLoadTimeout === 0) {
          } else {
            _failSafely(true);
          }
        }
      }
    }, _s.flashLoadTimeout);
  };
  _handleFocus = function() {
    function cleanup() {
      _event.remove(_win, 'focus', _handleFocus);
      _event.remove(_win, 'load', _handleFocus);
    }
    if (_isFocused || !_tryInitOnFocus) {
      cleanup();
      return true;
    }
    _okToDisable = true;
    _isFocused = true;
    if (_isSafari && _tryInitOnFocus) {
      _event.remove(_win, 'mousemove', _handleFocus);
    }
    _waitingForEI = false;
    cleanup();
    return true;
  };
  _showSupport = function() {
    var item, tests = [];
    if (_s.useHTML5Audio && _s.hasHTML5) {
      for (item in _s.audioFormats) {
        if (_s.audioFormats.hasOwnProperty(item)) {
          tests.push(item + ': ' + _s.html5[item] + (!_s.html5[item] && _hasFlash && _s.flash[item] ? ' (using flash)' : (_s.preferFlash && _s.flash[item] && _hasFlash ? ' (preferring flash)': (!_s.html5[item] ? ' (' + (_s.audioFormats[item].required ? 'required, ':'') + 'and no flash support)' : ''))));
        }
      }
    }
  };
  _initComplete = function(bNoDisable) {
    if (_didInit) {
      return false;
    }
    if (_s.html5Only) {
      _didInit = true;
      _initUserOnload();
      return true;
    }
    var wasTimeout = (_s.useFlashBlock && _s.flashLoadTimeout && !_s.getMoviePercent()),
        error;
    if (!wasTimeout) {
      _didInit = true;
      if (_disabled) {
        error = {type: (!_hasFlash && _needsFlash ? 'NO_FLASH' : 'INIT_TIMEOUT')};
      }
    }
    if (_disabled || bNoDisable) {
      if (_s.useFlashBlock && _s.oMC) {
        _s.oMC.className = _getSWFCSS() + ' ' + (_s.getMoviePercent() === null?_swfCSS.swfTimedout:_swfCSS.swfError);
      }
      _processOnEvents({type:'ontimeout', error:error});
      _catchError(error);
      return false;
    } else {
    }
    if (_s.waitForWindowLoad && !_windowLoaded) {
      _event.add(_win, 'load', _initUserOnload);
      return false;
    } else {
      _initUserOnload();
    }
    return true;
  };
  _init = function() {
    if (_didInit) {
      return false;
    }
    function _cleanup() {
      _event.remove(_win, 'load', _s.beginDelayedInit);
    }
    if (_s.html5Only) {
      if (!_didInit) {
        _cleanup();
        _s.enabled = true;
        _initComplete();
      }
      return true;
    }
    _initMovie();
    try {
      _flash._externalInterfaceTest(false);
      _setPolling(true, (_s.flashPollingInterval || (_s.useHighPerformance ? 10 : 50)));
      if (!_s.debugMode) {
        _flash._disableDebug();
      }
      _s.enabled = true;
      if (!_s.html5Only) {
        _event.add(_win, 'unload', _doNothing);
      }
    } catch(e) {
      _catchError({type:'JS_TO_FLASH_EXCEPTION', fatal:true});
      _failSafely(true);
      _initComplete();
      return false;
    }
    _initComplete();
    _cleanup();
    return true;
  };
  _domContentLoaded = function() {
    if (_didDCLoaded) {
      return false;
    }
    _didDCLoaded = true;
    _initDebug();
    if (!_hasFlash && _s.hasHTML5) {
      _s.useHTML5Audio = true;
      _s.preferFlash = false;
    }
    _testHTML5();
    _s.html5.usingFlash = _featureCheck();
    _needsFlash = _s.html5.usingFlash;
    _showSupport();
    if (!_hasFlash && _needsFlash) {
      _s.flashLoadTimeout = 1;
    }
    if (_doc.removeEventListener) {
      _doc.removeEventListener('DOMContentLoaded', _domContentLoaded, false);
    }
    _initMovie();
    return true;
  };
  _domContentLoadedIE = function() {
    if (_doc.readyState === 'complete') {
      _domContentLoaded();
      _doc.detachEvent('onreadystatechange', _domContentLoadedIE);
    }
    return true;
  };
  _winOnLoad = function() {
    _windowLoaded = true;
    _event.remove(_win, 'load', _winOnLoad);
  };
  _detectFlash();
  _event.add(_win, 'focus', _handleFocus);
  _event.add(_win, 'load', _handleFocus);
  _event.add(_win, 'load', _delayWaitForEI);
  _event.add(_win, 'load', _winOnLoad);
  if (_isSafari && _tryInitOnFocus) {
    _event.add(_win, 'mousemove', _handleFocus);
  }
  if (_doc.addEventListener) {
    _doc.addEventListener('DOMContentLoaded', _domContentLoaded, false);
  } else if (_doc.attachEvent) {
    _doc.attachEvent('onreadystatechange', _domContentLoadedIE);
  } else {
    _catchError({type:'NO_DOM2_EVENTS', fatal:true});
  }
  if (_doc.readyState === 'complete') {
    setTimeout(_domContentLoaded,100);
  }
}
// SM2_DEFER details: http://www.schillmania.com/projects/soundmanager2/doc/getstarted/#lazy-loading
if (typeof SM2_DEFER === 'undefined' || !SM2_DEFER) {
  soundManager = new SoundManager();
}
window.SoundManager = SoundManager;
window.soundManager = soundManager;
}(window));