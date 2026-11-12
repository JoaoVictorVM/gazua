(function () {
  "use strict";
  var panel = document.getElementById("filters");
  var damage = document.getElementById("filter-damage");
  var state = document.getElementById("filter-state");
  var counter = document.getElementById("visible-count");
  if (!panel || !damage || !state || !counter) {
    return;
  }
  var items = Array.prototype.slice.call(document.querySelectorAll("[data-item]"));
  function apply() {
    var shown = 0;
    items.forEach(function (item) {
      var visible =
        (damage.value === "" || item.getAttribute("data-damage") === damage.value) &&
        (state.value === "" || item.getAttribute("data-state") === state.value);
      item.hidden = !visible;
      if (visible) {
        shown += 1;
      }
    });
    counter.textContent = "Showing " + shown + " of " + items.length + " items.";
  }
  damage.addEventListener("change", apply);
  state.addEventListener("change", apply);
  panel.hidden = false;
  apply();
})();
