<template>
  <div class="filters-collapse border border-[--secondary-bg] rounded-lg bg-[--primary-bg-transparent-80] p-5 mb-5">
    <div @click="toggle" class="flex justify-between cursor-pointer select-none">
      <h3>Filters</h3>
      <i :class="['text-sm text-white fa-regular fa-chevron-down transition-transform duration-300', { 'rotate-180': isOpen }]"></i>
    </div>
    <transition name="slide">
      <div v-show="isOpen" class="mt-3 pt-3 select-none border-t border-[--secondary-bg]">
        <h5>Categories</h5>
        <div class="flex flex-wrap justify-start gap-3 pt-2 pb-3 text-md">
          <a
            v-for="c in categories"
            :key="c"
            :data-is-selected="c === category"
            :href="`/browse/${c}`"
            class="select-year p-2 rounded-lg border border-[--secondary-bg]"
          >
            {{ c }}
          </a>
        </div>
        <h5>Years</h5>
        <div class="flex flex-wrap justify-start gap-3 pt-2 text-md">
          <a
            v-for="y in years"
            :key="y"
            :data-is-selected="y === year"
            :href="`/browse/${category}/${y}`"
            class="select-year p-2 rounded-lg border border-[--secondary-bg]"
          >
            {{ y }}
          </a>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const props = defineProps({
  categories: {
    type: Array,
    required: true
  },
  years: {
    type: Array,
    required: true
  },
  category: {
    type: String,
    required: true
  },
  year: {
    type: String,
    required: true
  }
});

const isOpen = ref(true);

function toggle() {
  isOpen.value = !isOpen.value;
}
</script>

<style scoped>
.select-year {
  background: var(--primary-bg-transparent-80);
  transition: color 0.2s, background 0.2s;
}

.select-year[data-is-selected="true"],
.select-year:hover {
  background: var(--primary-color);
  color: var(--primary-bg) !important;
}

.slide-enter-active,
.slide-leave-active {
  transition: max-height 0.3s ease;
}
.slide-enter-from,
.slide-leave-to {
  max-height: 0;
  overflow: hidden;
}
.slide-enter-to,
.slide-leave-from {
  max-height: 500px;
  overflow: hidden;
}
</style>
