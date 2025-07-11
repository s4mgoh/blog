// from SimpleScrollbar
;(function(root, factory) {
  if (typeof exports === 'object') {
    module.exports = factory(window, document)
  } else {
    root.SimpleScrollbar = factory(window, document)
  }
})(this || window, function(w, d) {
  var raf = w.requestAnimationFrame || w.setImmediate || function(c) { return setTimeout(c, 0); };

  function initEl(el) {
    Object.defineProperty(el, 'data-simple-scrollbar', { value: new SimpleScrollbar(el), configurable: true });
  }

  function unbindEl(el) {
    if (!Object.prototype.hasOwnProperty.call(el, 'data-simple-scrollbar')) return;
    el['data-simple-scrollbar'].unBind();
    // Remove the elements property
    delete el['data-simple-scrollbar'];
  }

  // Mouse drag handler
  function dragDealer(el, context) {
    var lastPageY;

    el.addEventListener('mousedown', function(e) {
      lastPageY = e.pageY;
      el.classList.add('ss-grabbed');
      d.body.classList.add('ss-grabbed');

      d.addEventListener('mousemove', drag);
      d.addEventListener('mouseup', stop);

      return false;
    });

    function drag(e) {
      var delta = e.pageY - lastPageY;
      lastPageY = e.pageY;

      raf(function() {
        context.el.scrollTop += delta / context.scrollRatio;
      });
    }

    function stop() {
      el.classList.remove('ss-grabbed');
      d.body.classList.remove('ss-grabbed');
      d.removeEventListener('mousemove', drag);
      d.removeEventListener('mouseup', stop);
    }
  }

  // Constructor
  function ss(el) {
    this.target = el;
    this.content = el.firstElementChild;

    this.direction = w.getComputedStyle(this.target).direction;

    this.bar = '<div class="ss-scroll">';
    // Create a reference to the function binding to remove the event listeners
    this.mB = this.moveBar.bind(this);

    this.wrapper = d.createElement('div');
    this.wrapper.setAttribute('class', 'ss-wrapper');

    this.el = d.createElement('div');
    this.el.setAttribute('class', 'ss-content');

    if (this.direction === 'rtl') {
      this.el.classList.add('rtl');
    }

    this.wrapper.appendChild(this.el);

    while (this.target.firstChild) {
      this.el.appendChild(this.target.firstChild);
    }
    this.target.appendChild(this.wrapper);

    this.target.insertAdjacentHTML('beforeend', this.bar);
    this.bar = this.target.lastChild;

    dragDealer(this.bar, this);
    this.moveBar();

    w.addEventListener('resize', this.mB);
    this.el.addEventListener('scroll', this.mB);
    this.el.addEventListener('mouseenter', this.mB);

    this.target.classList.add('ss-container');

    var css = w.getComputedStyle(el);
  	if (css['height'] === '0px' && css['max-height'] !== '0px') {
    	el.style.height = css['max-height'];
    }

    this.unBind = function() {
      // Remove event listeners
      w.removeEventListener('resize', this.mB);
      this.el.removeEventListener('scroll', this.mB);
      this.el.removeEventListener('mouseenter', this.mB);
      
      this.target.classList.remove('ss-container');

      // Unwrap the initial content and remove remaining wrappers
      this.target.insertBefore(this.content, this.wrapper);
      this.target.removeChild(this.wrapper);

      // Remove the bar including its drag-dealer event listener
      this.target.removeChild(this.bar);
      this.bar = null; // make way for the garbage collector
    }
  }

  ss.prototype = {
    moveBar: function(e) {
      var totalHeight = this.el.scrollHeight,
          ownHeight = this.el.clientHeight,
          _this = this;

      this.scrollRatio = ownHeight / totalHeight;

      var isRtl = _this.direction === 'rtl';
      var right = isRtl ?
        (_this.target.clientWidth - _this.bar.clientWidth + 18) :
        (_this.target.clientWidth - _this.bar.clientWidth) * -1;

      raf(function() {
        // Hide scrollbar if no scrolling is possible
        if(_this.scrollRatio >= 1) {
          _this.bar.classList.add('ss-hidden')
        } else {
          _this.bar.classList.remove('ss-hidden')
          _this.bar.style.cssText = 'height:' + Math.max(_this.scrollRatio * 100, 10) + '%; top:' + (_this.el.scrollTop / totalHeight ) * 100 + '%;right:' + right + 'px;';
        }
      });
    }
  }

  function initAll() {
    var nodes = d.querySelectorAll('*[ss-container]');

    for (var i = 0; i < nodes.length; i++) {
      initEl(nodes[i]);
    }
  }

  function unbindAll() {
    var nodes = d.querySelectorAll('.ss-container');

    for (var i = 0; i < nodes.length; i++) {
      unbindEl(nodes[i]);
    }
  }

  d.addEventListener('astro:page-load', initAll);
  ss.initEl = initEl;
  ss.initAll = initAll;
  ss.unbindEl = unbindEl;
  ss.unbindAll = unbindAll;

  var SimpleScrollbar = ss;
  return SimpleScrollbar;
});
