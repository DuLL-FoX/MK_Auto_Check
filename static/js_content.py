def get_js_content() -> str:
    return """
document.addEventListener('DOMContentLoaded', () => {
  const app = {
    init() {
      this.initSidebar();
      this.initTabs();
      this.initSearch();
      this.initTableSorting();
      this.initCopyButtons();
      this.initThemeToggle();
      this.initBackToTop();
      this.initFilters();
      this.initSorting();
    },

    getElement(selector) {
      const element = document.querySelector(selector);
      return element;
    },

    getElements(selector) {
      return document.querySelectorAll(selector);
    },

    preferences: {
      get(key, defaultValue = null) {
        return localStorage.getItem(key) || defaultValue;
      },

      set(key, value) {
        localStorage.setItem(key, value);
      },

      getBoolean(key, defaultValue = false) {
        return localStorage.getItem(key) === 'true' || defaultValue;
      }
    },

    initSidebar() {
      const menuToggle = this.getElement('.menu-toggle');
      const appContainer = this.getElement('.app-container');

      if (menuToggle && appContainer) {
        menuToggle.addEventListener('click', () => {
          appContainer.classList.toggle('collapsed-sidebar');
          this.preferences.set('sidebarCollapsed', appContainer.classList.contains('collapsed-sidebar'));
        });

        if (this.preferences.getBoolean('sidebarCollapsed')) {
          appContainer.classList.add('collapsed-sidebar');
        }
      }

      this.initSidebarDropdowns(appContainer);
      this.initNavHighlighting();
      this.initPlayerLinks();
    },

    initSidebarDropdowns(appContainer) {
      const dropdowns = this.getElements('.sidebar-dropdown > a');

      dropdowns.forEach(dropdown => {
        dropdown.addEventListener('click', e => {
          e.preventDefault();
          const parent = dropdown.parentElement;
          parent.classList.toggle('active');

          dropdowns.forEach(otherDropdown => {
            if (otherDropdown !== dropdown && otherDropdown.parentElement.classList.contains('active')) {
              otherDropdown.parentElement.classList.remove('active');
              const submenu = otherDropdown.nextElementSibling;
              if (submenu) submenu.style.display = 'none';
            }
          });

          if (appContainer.classList.contains('collapsed-sidebar')) {
            return;
          }

          const submenu = dropdown.nextElementSibling;
          if (submenu) {
            submenu.style.display = submenu.style.display === 'block' ? 'none' : 'block';
          }

          const dropdownId = parent.getAttribute('data-id') || 
                            dropdown.textContent.trim().replace(/\\s+/g, '-').toLowerCase();
          this.preferences.set(`dropdown-${dropdownId}`, parent.classList.contains('active'));
        });

        const dropdownId = dropdown.parentElement.getAttribute('data-id') || 
                          dropdown.textContent.trim().replace(/\\s+/g, '-').toLowerCase();
        const isActive = this.preferences.getBoolean(`dropdown-${dropdownId}`);

        if (isActive) {
          dropdown.parentElement.classList.add('active');
          const submenu = dropdown.nextElementSibling;
          if (submenu && !appContainer.classList.contains('collapsed-sidebar')) {
            submenu.style.display = 'block';
          }
        }
      });

      this.getElements('.sidebar-dropdown.active .sidebar-submenu').forEach(submenu => {
        if (!appContainer.classList.contains('collapsed-sidebar')) {
          submenu.style.display = 'block';
        }
      });
    },

    initNavHighlighting() {
      const navLinks = this.getElements('.sidebar-nav a:not([data-filter]):not([data-sort]):not([href^="#player-"])');

      navLinks.forEach(link => {
        link.addEventListener('click', () => {
          navLinks.forEach(navLink => {
            navLink.parentElement.classList.remove('active');
          });
          link.parentElement.classList.add('active');
          this.preferences.set('activeNavLink', link.getAttribute('href'));
        });

        const activeNavLink = this.preferences.get('activeNavLink');
        if (activeNavLink === link.getAttribute('href')) {
          link.parentElement.classList.add('active');
        }
      });
    },

    initPlayerLinks() {
      this.getElements('.player-link').forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          const playerId = link.getAttribute('href').substring(1);
          const playerElement = document.getElementById(playerId);

          if (playerElement) {
            this.getElements('.report-card').forEach(card => {
              card.classList.remove('highlight-pulse');
            });

            const reportCard = playerElement.closest('.report-card');
            if (reportCard) {
              reportCard.classList.add('highlight-pulse');
              reportCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
              setTimeout(() => {
                reportCard.classList.remove('highlight-pulse');
              }, 2000);
              this.updateActiveFilterTags('player', link.textContent.trim());
            }
          }
        });
      });
    },

    initTabs() {
      const tabButtons = this.getElements('.tab');

      tabButtons.forEach(button => {
        button.addEventListener('click', () => {
          const tabId = button.getAttribute('data-tab');
          const tabsContainer = button.closest('.tabs');
          const contentContainer = button.closest('.tabs-container');
          tabsContainer.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
          button.classList.add('active');
          contentContainer.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
          });
          document.getElementById(tabId).classList.add('active');
          const reportId = tabId.split('-').slice(0, 2).join('-');
          this.preferences.set(`tab-${reportId}`, tabId);
        });
      });

      this.getElements('.tab-content').forEach(content => {
        const contentId = content.id;
        const reportId = contentId.split('-').slice(0, 2).join('-');
        const savedTabId = this.preferences.get(`tab-${reportId}`);

        if (savedTabId === contentId) {
          const tabButton = this.getElement(`.tab[data-tab="${contentId}"]`);
          if (tabButton) {
            tabButton.click();
          }
        }
      });
    },

    initSearch() {
      const searchInput = this.getElement('#search-input');
      const clearSearch = this.getElement('#clear-search');

      if (searchInput) {
        const savedSearch = this.preferences.get('searchTerm');
        if (savedSearch) {
          searchInput.value = savedSearch;
          this.performSearch(savedSearch);
        }

        searchInput.addEventListener('input', () => {
          const searchTerm = searchInput.value.toLowerCase();
          this.preferences.set('searchTerm', searchTerm);
          this.performSearch(searchTerm);
        });

        searchInput.addEventListener('keydown', e => {
          if (e.key === 'Enter') {
            e.preventDefault();
            this.performSearch(searchInput.value.toLowerCase());
          }
        });
      }

      if (clearSearch) {
        clearSearch.addEventListener('click', () => {
          searchInput.value = '';
          this.preferences.set('searchTerm', '');
          this.performSearch('');
          searchInput.focus();
        });
      }

      this.updateVisibleCount();
    },

    performSearch(searchTerm) {
      const reports = this.getElements('.report-card');

      reports.forEach(report => {
        if (searchTerm === '') {
          const activeFilter = this.getElement('.filter-link.active');
          if (activeFilter) {
            const filter = activeFilter.getAttribute('data-filter');
            this.applyFilter(filter, report);
          } else {
            report.style.display = '';
          }
        } else {
          const text = report.textContent.toLowerCase();
          const playerName = report.getAttribute('data-player-name')?.toLowerCase() || '';
          const hwid = report.querySelector('.hwid-value')?.textContent.toLowerCase() || '';
          const ipAddress = report.querySelector('.info-item:nth-child(3) .value')?.textContent.toLowerCase() || '';

          if (
            text.includes(searchTerm) || 
            playerName.includes(searchTerm) || 
            hwid.includes(searchTerm) || 
            ipAddress.includes(searchTerm)
          ) {
            report.style.display = '';
          } else {
            report.style.display = 'none';
          }
        }
      });

      this.updateVisibleCount();
    },

    updateVisibleCount() {
      const visibleReports = this.getElements('.report-card:not([style*="display: none"])').length;
      const totalReports = this.getElements('.report-card').length;

      const visibleCountElement = this.getElement('#visible-count');
      const totalCountElement = this.getElement('#total-count');

      if (visibleCountElement) {
        visibleCountElement.textContent = visibleReports;
      }

      if (totalCountElement) {
        totalCountElement.textContent = totalReports;
      }
    },

    initTableSorting() {
      this.getElements('th.sortable').forEach(headerCell => {
        headerCell.addEventListener('click', () => {
          const table = headerCell.closest('table');
          const headerIndex = Array.prototype.indexOf.call(headerCell.parentElement.children, headerCell);
          const currentIsAscending = headerCell.classList.contains('th-sort-asc');

          table.querySelectorAll('th').forEach(th => {
            th.classList.remove('th-sort-asc', 'th-sort-desc');
          });

          headerCell.classList.toggle('th-sort-asc', !currentIsAscending);
          headerCell.classList.toggle('th-sort-desc', currentIsAscending);

          const tableBody = table.querySelector('tbody');
          const rows = Array.from(tableBody.querySelectorAll('tr'));
          const sortedRows = this.sortTableRows(rows, headerIndex, currentIsAscending);
          rows.forEach(row => tableBody.removeChild(row));
          sortedRows.forEach(row => tableBody.appendChild(row));
        });
      });
    },

    sortTableRows(rows, columnIndex, isCurrentlyAscending) {
      return rows.sort((a, b) => {
        const aValue = a.children[columnIndex].textContent.trim();
        const bValue = b.children[columnIndex].textContent.trim();
        const aNum = parseFloat(aValue);
        const bNum = parseFloat(bValue);

        if (!isNaN(aNum) && !isNaN(bNum)) {
          return isCurrentlyAscending ? bNum - aNum : aNum - bNum;
        }
        return isCurrentlyAscending 
          ? bValue.localeCompare(aValue) 
          : aValue.localeCompare(bValue);
      });
    },

    initCopyButtons() {
      this.getElements('.copy-btn').forEach(button => {
        button.addEventListener('click', () => {
          const textToCopy = button.getAttribute('data-copy');
          navigator.clipboard.writeText(textToCopy)
            .then(() => {
              const originalTitle = button.getAttribute('title');
              button.setAttribute('title', 'Copied!');
              button.classList.add('copied');
              setTimeout(() => {
                button.setAttribute('title', originalTitle || '');
                button.classList.remove('copied');
              }, 2000);
            })
            .catch(err => {
              console.error('Could not copy text: ', err);
            });
        });
      });
    },

    initThemeToggle() {
      const themeToggle = this.getElement('#theme-toggle');
      const savedTheme = this.preferences.get('theme', 'dark');
      document.documentElement.setAttribute('data-theme', savedTheme);

      if (themeToggle) {
        const icon = themeToggle.querySelector('i');
        if (savedTheme === 'dark') {
          icon.className = 'fas fa-sun';
        } else {
          icon.className = 'fas fa-moon';
        }

        themeToggle.addEventListener('click', () => {
          const currentTheme = document.documentElement.getAttribute('data-theme');
          const icon = themeToggle.querySelector('i');

          if (currentTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'light');
            this.preferences.set('theme', 'light');
            icon.className = 'fas fa-moon';
          } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            this.preferences.set('theme', 'dark');
            icon.className = 'fas fa-sun';
          }
        });
      }
    },

    initBackToTop() {
      const backToTop = this.getElement('#back-to-top');

      if (backToTop) {
        window.addEventListener('scroll', () => {
          if (window.pageYOffset > 300) {
            backToTop.classList.add('visible');
          } else {
            backToTop.classList.remove('visible');
          }
        });

        backToTop.addEventListener('click', () => {
          window.scrollTo({
            top: 0,
            behavior: 'smooth'
          });
        });
      }
    },

    initFilters() {
      const filterLinks = this.getElements('.filter-link');
      const activeFiltersContainer = this.getElement('#active-filters');

      filterLinks.forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          filterLinks.forEach(lnk => lnk.classList.remove('active'));
          link.classList.add('active');
          const filter = link.getAttribute('data-filter');
          this.getElements('.report-card').forEach(report => {
            this.applyFilter(filter, report);
          });
          const filterName = link.textContent.trim();
          this.updateActiveFilterTags('filter', filterName);
          this.preferences.set('activeFilter', filter);
          this.preferences.set('activeFilterName', filterName);
          this.updateVisibleCount();
        });
      });

      if (activeFiltersContainer) {
        activeFiltersContainer.addEventListener('click', e => {
          if (e.target.closest('.filter-tag')) {
            const filterTag = e.target.closest('.filter-tag');
            const filter = filterTag.getAttribute('data-filter');

            if (filter === 'all') {
              this.getElements('.filter-tag').forEach(tag => {
                if (tag !== filterTag) {
                  tag.remove();
                }
              });
              this.getElements('.report-card').forEach(report => {
                this.applyFilter('all', report);
              });
              this.getElement('.filter-link[data-filter="all"]').classList.add('active');
              this.getElements('.filter-link').forEach(link => {
                if (link.getAttribute('data-filter') !== 'all') {
                  link.classList.remove('active');
                }
              });
              this.preferences.set('activeFilter', 'all');
              this.preferences.set('activeFilterName', 'All Reports');
            } else {
              filterTag.remove();
              if (this.getElements('.filter-tag').length === 0) {
                const allTag = document.createElement('span');
                allTag.className = 'filter-tag active';
                allTag.setAttribute('data-filter', 'all');
                allTag.innerHTML = 'All Reports <i class="fas fa-times-circle"></i>';
                activeFiltersContainer.appendChild(allTag);
                this.getElements('.report-card').forEach(report => {
                  this.applyFilter('all', report);
                });
                this.getElement('.filter-link[data-filter="all"]').classList.add('active');
                this.preferences.set('activeFilter', 'all');
                this.preferences.set('activeFilterName', 'All Reports');
              }
            }
            this.updateVisibleCount();
          }
        });
      }

      const savedFilter = this.preferences.get('activeFilter');
      const savedFilterName = this.preferences.get('activeFilterName');

      if (savedFilter && savedFilterName) {
        this.getElements('.report-card').forEach(report => {
          this.applyFilter(savedFilter, report);
        });
        const filterLink = this.getElement(`.filter-link[data-filter="${savedFilter}"]`);
        if (filterLink) {
          filterLinks.forEach(link => link.classList.remove('active'));
          filterLink.classList.add('active');
        }
        this.updateActiveFilterTags('filter', savedFilterName);
        this.updateVisibleCount();
      }
    },

    updateActiveFilterTags(type, name) {
      const activeFiltersContainer = this.getElement('#active-filters');
      if (!activeFiltersContainer) return;

      if (type === 'filter') {
        this.getElements('.filter-tag[data-type="filter"]').forEach(tag => tag.remove());
        this.getElements('.filter-tag[data-type="player"]').forEach(tag => tag.remove());
        const filterTag = document.createElement('span');
        filterTag.className = 'filter-tag active';
        filterTag.setAttribute('data-filter', this.getElement('.filter-link.active').getAttribute('data-filter'));
        filterTag.setAttribute('data-type', 'filter');
        filterTag.innerHTML = `${name} <i class="fas fa-times-circle"></i>`;
        activeFiltersContainer.appendChild(filterTag);
      } else if (type === 'player') {
        const existingPlayerTag = this.getElement('.filter-tag[data-type="player"]');
        if (existingPlayerTag) {
          existingPlayerTag.innerHTML = `Player: ${name} <i class="fas fa-times-circle"></i>`;
        } else {
          const playerTag = document.createElement('span');
          playerTag.className = 'filter-tag active';
          playerTag.setAttribute('data-type', 'player');
          playerTag.innerHTML = `Player: ${name} <i class="fas fa-times-circle"></i>`;
          activeFiltersContainer.appendChild(playerTag);
        }
        const allTag = this.getElement('.filter-tag[data-filter="all"]');
        if (allTag) {
          allTag.remove();
        }
      }
    },

    applyFilter(filter, report) {
      if (filter === 'all') {
        report.style.display = '';
        return true;
      }

      let match = false;

      if (filter === 'confidence-high') {
        match = report.classList.contains('confidence-high');
      } else if (filter === 'confidence-medium') {
        match = report.classList.contains('confidence-medium');
      } else if (filter === 'confidence-low') {
        match = report.classList.contains('confidence-low');
      } else if (filter === 'verdict-potential-bypass') {
        const verdict = report.getAttribute('data-verdict');
        match = verdict === 'POTENTIAL BYPASS' || verdict === 'POTENTIAL_BYPASS';
      } else if (filter === 'verdict-suspicious') {
        match = report.getAttribute('data-verdict') === 'SUSPICIOUS';
      } else if (filter === 'verdict-banned') {
        match = report.getAttribute('data-verdict') === 'BANNED';
      } else if (filter === 'verdict-clean') {
        match = report.getAttribute('data-verdict') === 'CLEAN';
      } else if (filter === 'vpn-detected') {
        match = report.classList.contains('vpn-detected');
      } else if (filter === 'hwid-erased') {
        match = report.classList.contains('hwid-erased');
      } else if (filter.startsWith('player-')) {
        const playerName = filter.substring(7);
        match = report.getAttribute('data-player-name') === playerName;
      }
      report.style.display = match ? '' : 'none';
      return match;
    },

    initSorting() {
      const sortLinks = this.getElements('.sort-link');

      sortLinks.forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          sortLinks.forEach(lnk => lnk.classList.remove('active'));
          link.classList.add('active');
          const sortType = link.getAttribute('data-sort');
          this.sortReports(sortType);
          this.preferences.set('activeSort', sortType);
        });
      });

      const savedSort = this.preferences.get('activeSort');
      if (savedSort) {
        this.sortReports(savedSort);
        const sortLink = this.getElement(`.sort-link[data-sort="${savedSort}"]`);
        if (sortLink) {
          sortLinks.forEach(link => link.classList.remove('active'));
          sortLink.classList.add('active');
        }
      }
    },

    sortReports(sortType) {
      const container = this.getElement('#reports-container');
      if (!container) return;
      const reports = Array.from(container.querySelectorAll('.report-card'));
      reports.sort((a, b) => {
        switch (sortType) {
          case 'name-asc':
            return a.getAttribute('data-player-name').localeCompare(b.getAttribute('data-player-name'));
          case 'name-desc':
            return b.getAttribute('data-player-name').localeCompare(a.getAttribute('data-player-name'));
          case 'bans-desc':
            return parseInt(b.getAttribute('data-ban-count') || 0) - parseInt(a.getAttribute('data-ban-count') || 0);
          case 'confidence-desc':
            const confidenceOrder = { 'confidence-high': 3, 'confidence-medium': 2, 'confidence-low': 1 };
            const aConfidence = a.classList.contains('confidence-high') ? 'confidence-high' : 
                               (a.classList.contains('confidence-medium') ? 'confidence-medium' : 'confidence-low');
            const bConfidence = b.classList.contains('confidence-high') ? 'confidence-high' : 
                               (b.classList.contains('confidence-medium') ? 'confidence-medium' : 'confidence-low');
            return confidenceOrder[bConfidence] - confidenceOrder[aConfidence];
          default:
            return 0;
        }
      });
      reports.forEach(report => {
        container.appendChild(report);
      });
    }
  };

  app.init();
});

function filterByIP(ip) {
  const searchInput = document.querySelector('#search-input');
  if (searchInput) {
    searchInput.value = ip;
    const event = new Event('input', { bubbles: true });
    searchInput.dispatchEvent(event);
  }
}

function filterByHWID(hwid) {
  const searchInput = document.querySelector('#search-input');
  if (searchInput) {
    searchInput.value = hwid;
    const event = new Event('input', { bubbles: true });
    searchInput.dispatchEvent(event);
  }
}
"""
