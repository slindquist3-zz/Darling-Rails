import { FETCH_PRODUCTS } from '../actions/fetchProducts'

export default function(state = [], action) {
  switch(action.type) {
    case FETCH_PRODUCTS:
      return [ action.payload.data, ...state ]
  }
  return state;
}
